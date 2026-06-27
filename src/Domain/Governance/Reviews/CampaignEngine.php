<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Governance\Reviews;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Collection;
use Padosoft\Iam\Domain\Audit\Pii\AuditRecorder;
use Padosoft\Iam\Domain\Authorization\Models\Grant;
use Padosoft\Iam\Domain\Governance\Reviews\Models\ReviewCampaign;
use Padosoft\Iam\Domain\Governance\Reviews\Models\ReviewItem;

/**
 * Campaign engine delle Access Review (doc 14 §3). Genera gli item da certificare a partire dallo
 * scope, li arricchisce con i segnali smart (snapshot immutabile), applica le decisioni dei reviewer
 * e, alla chiusura, l'azione on_unconfirmed sui pending. Ogni revoca è tracciata in audit (§invariante
 * #4: ogni mutazione di grant è auditata).
 */
final class CampaignEngine
{
    public function __construct(
        private readonly ReviewSignals $signals = new ReviewSignals,
        private readonly ?AuditRecorder $audit = null,
    ) {}

    /**
     * Apre la campagna: genera un ReviewItem per ogni grant ATTIVO nello scope, con snapshot dei
     * segnali smart. Idempotente sul (campaign, grant): re-aprire non duplica gli item.
     *
     * @return int numero di item generati in questa apertura
     */
    public function open(ReviewCampaign $campaign): int
    {
        if ($campaign->status === 'completed') {
            throw new \RuntimeException("Campagna {$campaign->id} già completata: non riapribile.");
        }

        $created = 0;
        foreach ($this->scopedGrants($campaign)->cursor() as $grant) {
            $exists = ReviewItem::query()
                ->where('campaign_id', $campaign->id)
                ->where('grant_id', $grant->id)
                ->exists();
            if ($exists) {
                continue;
            }

            ReviewItem::create([
                'campaign_id' => $campaign->id,
                'grant_id' => $grant->id,
                'reviewer_subject' => $this->resolveReviewer($campaign, $grant),
                'signals_json' => $this->signals->for($grant),
            ]);
            $created++;
        }

        $campaign->forceFill(['status' => 'running', 'opened_at' => now()])->save();

        return $created;
    }

    /**
     * Decisione di un reviewer su un singolo item. `revoked` revoca il grant (e lo audita);
     * `approved`/`delegated` non toccano il grant. Solo gli item ancora `pending` sono decidibili.
     */
    public function decide(ReviewItem $item, string $decision, string $decidedBy, ?string $note = null): void
    {
        if ($item->decision !== 'pending') {
            throw new \RuntimeException("Item {$item->id} già deciso ({$item->decision}).");
        }
        if (!in_array($decision, ['approved', 'revoked', 'delegated'], true)) {
            throw new \InvalidArgumentException("Decisione non valida: {$decision}.");
        }

        if ($decision === 'revoked') {
            $this->revokeGrant($item, $decidedBy, $note ?? 'access-review: revoca reviewer');
        }

        $item->forceFill([
            'decision' => $decision,
            'decided_at' => now(),
            'decided_by' => $decidedBy,
            'note' => $note,
        ])->save();
    }

    /**
     * Chiude la campagna applicando on_unconfirmed ai soli item ancora `pending` (doc 14 §3):
     * `revoke` revoca il grant, `keep` lo conferma (approved), `suspend` — non avendo v1 una
     * sospensione di grant — è trattato fail-closed come revoca (più sicuro che lasciare l'accesso).
     *
     * @return int numero di item pending processati
     */
    public function close(ReviewCampaign $campaign): int
    {
        $action = $campaign->on_unconfirmed;
        $processed = 0;

        /** @var Collection<int, ReviewItem> $pending */
        $pending = $campaign->items()->where('decision', 'pending')->get();
        foreach ($pending as $item) {
            if ($action === 'keep') {
                $item->forceFill([
                    'decision' => 'approved',
                    'decided_at' => now(),
                    'decided_by' => 'system:access-review',
                    'note' => 'on_unconfirmed=keep',
                ])->save();
            } else {
                // revoke | suspend (fail-closed)
                $this->revokeGrant($item, 'system:access-review', "on_unconfirmed={$action}");
                $item->forceFill([
                    'decision' => 'revoked',
                    'decided_at' => now(),
                    'decided_by' => 'system:access-review',
                    'note' => "on_unconfirmed={$action}",
                ])->save();
            }
            $processed++;
        }

        $campaign->forceFill(['status' => 'completed', 'closed_at' => now()])->save();

        return $processed;
    }

    /**
     * Reviewer ancora da sollecitare: i soggetti distinti con almeno un item pending.
     *
     * @return list<string>
     */
    public function remind(ReviewCampaign $campaign): array
    {
        /** @var list<string> $reviewers */
        $reviewers = $campaign->items()
            ->where('decision', 'pending')
            ->whereNotNull('reviewer_subject')
            ->distinct()
            ->pluck('reviewer_subject')
            ->all();

        return $reviewers;
    }

    private function revokeGrant(ReviewItem $item, string $by, string $reason): void
    {
        $grant = $item->grant()->first();
        if ($grant === null || $grant->revoked_at !== null) {
            return; // grant già rimosso/revocato: niente da fare (idempotente)
        }

        $grant->revoke($by);

        ($this->audit ?? app(AuditRecorder::class))->record([
            'stream' => 'governance',
            'event_type' => 'iam.grant.revoked',
            'target_type' => 'grant',
            'target_id' => $grant->id,
            'organization_id' => $grant->organization_id,
            'metadata_json' => [
                'source' => 'access-review',
                'campaign_id' => $item->campaign_id,
                'review_item_id' => $item->id,
                'reason' => $reason,
                'revoked_by' => $by,
            ],
        ]);
    }

    /**
     * Grant attivi che ricadono nello scope della campagna. Filtri additivi e fail-closed:
     * uno scope vuoto certifica TUTTI i grant attivi (full inventory).
     *
     * @return Builder<Grant>
     */
    private function scopedGrants(ReviewCampaign $campaign): Builder
    {
        $scope = $campaign->scope_json ?? [];
        $query = Grant::query()->active();

        if ($campaign->organization_id !== null) {
            $query->where(fn (Builder $w) => $w->whereNull('organization_id')->orWhere('organization_id', $campaign->organization_id));
        }

        $apps = $this->stringList($scope['application_keys'] ?? null);
        if ($apps !== []) {
            $query->whereIn('application_key', $apps);
        }

        $types = $this->stringList($scope['privilege_types'] ?? null);
        if ($types !== []) {
            $query->whereIn('privilege_type', $types);
        }

        $subjects = $this->stringList($scope['subject_types'] ?? null);
        if ($subjects !== []) {
            $query->whereIn('subject_type', $subjects);
        }

        if (($scope['only_privileged'] ?? false) === true) {
            $query->where('is_privileged', true);
        }

        return $query;
    }

    private function resolveReviewer(ReviewCampaign $campaign, Grant $grant): ?string
    {
        // v1: strategia 'named' → reviewer esplicito nello scope. 'manager'/'resource_owner'
        // richiedono la directory sync / l'app-owner registry (v2): per ora restano null
        // (l'item è comunque visibile a un admin con iam:access_review.manage).
        if ($campaign->reviewer_strategy === 'named') {
            $named = $campaign->scope_json['reviewer'] ?? null;

            return is_string($named) && $named !== '' ? $named : null;
        }

        return null;
    }

    /**
     * @return list<string>
     */
    private function stringList(mixed $value): array
    {
        if (!is_array($value)) {
            return [];
        }

        $out = [];
        foreach ($value as $v) {
            if (is_string($v) && $v !== '') {
                $out[] = $v;
            }
        }

        return $out;
    }
}
