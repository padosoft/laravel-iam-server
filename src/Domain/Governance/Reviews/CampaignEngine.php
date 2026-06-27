<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Governance\Reviews;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\DB;
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
        // Apribile solo da draft (prima apertura) o running (riapertura idempotente per aggiungere
        // grant nuovi nello scope). Una campagna completed/expired NON si riapre (fail-closed).
        if (!in_array($campaign->status, ['draft', 'running'], true)) {
            throw new \RuntimeException("Campagna {$campaign->id} in stato {$campaign->status}: non apribile.");
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

            // forceFill: reviewer_subject/signals_json sono uno snapshot non mass-assignable.
            $item = (new ReviewItem)->forceFill([
                'campaign_id' => $campaign->id,
                'grant_id' => $grant->id,
                'reviewer_subject' => $this->resolveReviewer($campaign, $grant),
                'signals_json' => $this->signals->for($grant),
            ]);
            try {
                $item->save();
                $created++;
            } catch (UniqueConstraintViolationException) {
                // Race con un'altra apertura concorrente: l'unique (campaign_id, grant_id) ha già
                // creato l'item → niente duplicato, niente conteggio. Idempotenza garantita dal DB.
            }
        }

        // opened_at si valorizza SOLO alla prima apertura: una riapertura non sposta la data d'inizio.
        $campaign->forceFill([
            'status' => 'running',
            'opened_at' => $campaign->opened_at ?? now(),
        ])->save();

        return $created;
    }

    /**
     * Decisione di un reviewer su un singolo item. `revoked` revoca il grant (e lo audita);
     * `approved`/`delegated` non toccano il grant. Solo gli item ancora `pending` sono decidibili.
     */
    public function decide(ReviewItem $item, string $decision, string $decidedBy, ?string $note = null): void
    {
        if (!in_array($decision, ['approved', 'revoked', 'delegated'], true)) {
            throw new \InvalidArgumentException("Decisione non valida: {$decision}.");
        }

        // Transazione + lock di riga: due reviewer che agiscono sullo stesso item non possono fare
        // last-write-wins né revocare due volte; il ricontrollo `pending` avviene SOTTO il lock.
        DB::transaction(function () use ($item, $decision, $decidedBy, $note): void {
            $locked = ReviewItem::query()->whereKey($item->id)->lockForUpdate()->first();
            if ($locked === null || $locked->decision !== 'pending') {
                throw new \RuntimeException("Item {$item->id} già deciso o inesistente.");
            }

            if ($decision === 'revoked') {
                $this->revokeGrant($locked, $decidedBy, $note ?? 'access-review: revoca reviewer');
            }

            $locked->forceFill([
                'decision' => $decision,
                'decided_at' => now(),
                'decided_by' => $decidedBy,
                'note' => $note,
            ])->save();
        });

        $item->refresh();
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
        // Chiudibile solo da running: non si chiude una draft (mai aperta) né si ri-chiude una
        // completed (closed_at/decisioni non vanno sovrascritte → storia immutabile).
        if ($campaign->status !== 'running') {
            throw new \RuntimeException("Campagna {$campaign->id} in stato {$campaign->status}: non chiudibile (attesa: running).");
        }

        $action = $campaign->on_unconfirmed;
        $processed = 0;

        /** @var Collection<int, ReviewItem> $pending */
        $pending = $campaign->items()->where('decision', 'pending')->get();
        foreach ($pending as $item) {
            // Stessa garanzia di decide(): lock + ricontrollo pending, così un reviewer che decide
            // mentre la campagna si chiude non viene sovrascritto (no doppia azione sul grant).
            DB::transaction(function () use ($item, $action): void {
                $locked = ReviewItem::query()->whereKey($item->id)->lockForUpdate()->first();
                if ($locked === null || $locked->decision !== 'pending') {
                    return;
                }

                if ($action === 'keep') {
                    $locked->forceFill([
                        'decision' => 'approved',
                        'decided_at' => now(),
                        'decided_by' => 'system:access-review',
                        'note' => 'on_unconfirmed=keep',
                    ])->save();
                } else {
                    // revoke | suspend (fail-closed): qualunque azione diversa da keep rimuove l'accesso.
                    $this->revokeGrant($locked, 'system:access-review', "on_unconfirmed={$action}");
                    $locked->forceFill([
                        'decision' => 'revoked',
                        'decided_at' => now(),
                        'decided_by' => 'system:access-review',
                        'note' => "on_unconfirmed={$action}",
                    ])->save();
                }
            });
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

        // Isolamento cross-tenant (fail-closed): una campagna di un'org certifica SOLO i grant di
        // quell'org. I grant globali (organization_id null) valgono per tutti i tenant → li può
        // certificare/revocare unicamente una campagna globale (organization_id null = full inventory),
        // mai una campagna di un singolo tenant, che altrimenti danneggerebbe gli altri.
        if ($campaign->organization_id !== null) {
            $query->where('organization_id', $campaign->organization_id);
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
