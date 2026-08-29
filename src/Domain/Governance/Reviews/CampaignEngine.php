<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Governance\Reviews;

use Illuminate\Support\Collection;
use Illuminate\Support\Facades\DB;
use Padosoft\Iam\Domain\Audit\Pii\AuditRecorder;
use Padosoft\Iam\Domain\Governance\Reviews\Models\ReviewCampaign;
use Padosoft\Iam\Domain\Governance\Reviews\Models\ReviewItem;
use Padosoft\Iam\Domain\Governance\Reviews\Reviewable\GrantReviewableSource;
use Padosoft\Iam\Domain\Governance\Reviews\Reviewable\ReviewableRegistry;
use Padosoft\Iam\Domain\Governance\Reviews\Reviewable\ReviewableSource;
use Padosoft\Iam\Domain\Governance\Reviews\Reviewable\UnknownReviewableSource;

/**
 * Campaign engine delle Access Review (doc 14 §3). Genera gli item da certificare a partire dallo
 * scope, li arricchisce con i segnali smart (snapshot immutabile), applica le decisioni dei reviewer
 * e, alla chiusura, l'azione on_unconfirmed sui pending. Ogni revoca è tracciata in audit (§invariante
 * #4: ogni mutazione di grant è auditata).
 *
 * L'engine NON sa cosa sta certificando: ogni categoria di accesso è una {@see ReviewableSource}
 * registrata nel {@see ReviewableRegistry}. I grant RBAC/ABAC sono la sorgente built-in; le
 * delegation grant arrivano da `laravel-iam-agents`. Orchestrare la campagna e conoscere il dominio
 * di un accesso sono due responsabilità diverse, e tenerle separate è ciò che permette a un modulo
 * opzionale di entrare nell'IGA senza toccare il core.
 */
final class CampaignEngine
{
    public function __construct(
        private readonly ?ReviewableRegistry $registry = null,
        private readonly ?AuditRecorder $audit = null,
    ) {}

    /**
     * Apre la campagna: genera un ReviewItem per ogni accesso ATTIVO nello scope, in ogni sorgente
     * inclusa, con snapshot dei segnali smart. Idempotente sul (campaign, type, id): re-aprire non
     * duplica gli item — e aggiunge quelli di una sorgente registrata dopo la prima apertura.
     *
     * @return int numero di item generati in questa apertura
     */
    public function open(ReviewCampaign $campaign): int
    {
        // IAM-17: TOCTOU. Lock the campaign row and re-check its status UNDER the lock, mirroring cancel().
        // The whole generation runs in the locked transaction so two concurrent open()s (or an open racing
        // a close/cancel) cannot both pass the guard. Because the lock serialises opens, the (campaign,grant)
        // exists-check is authoritative and the previous catch(UniqueConstraintViolation) — which would poison
        // a Postgres transaction on the first hit — is no longer needed.
        return DB::transaction(function () use ($campaign): int {
            $locked = ReviewCampaign::query()->whereKey($campaign->id)->lockForUpdate()->first();
            $state = $locked->status ?? 'inesistente';
            // Apribile solo da draft (prima apertura) o running (riapertura idempotente). completed/expired NO.
            if ($locked === null || !in_array($state, ['draft', 'running'], true)) {
                throw new \RuntimeException("Campagna {$campaign->id} in stato {$state}: non apribile.");
            }

            $created = 0;
            foreach ($this->sourcesFor($locked) as $source) {
                foreach ($source->scoped($locked) as $ref) {
                    $exists = ReviewItem::query()
                        ->where('campaign_id', $locked->id)
                        ->where('reviewable_type', $ref->type)
                        ->where('reviewable_id', $ref->id)
                        ->exists();
                    if ($exists) {
                        continue;
                    }

                    // forceFill: reviewer_subject/signals_json sono uno snapshot non mass-assignable.
                    (new ReviewItem)->forceFill([
                        'campaign_id' => $locked->id,
                        'reviewable_type' => $ref->type,
                        'reviewable_id' => $ref->id,
                        'reviewer_subject' => $ref->reviewer,
                        'signals_json' => $ref->signals,
                    ])->save();
                    $created++;
                }
            }

            // opened_at si valorizza SOLO alla prima apertura: una riapertura non sposta la data d'inizio.
            $locked->forceFill([
                'status' => 'running',
                'opened_at' => $locked->opened_at ?? now(),
            ])->save();

            return $created;
        });
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
                $this->revokeReviewable($locked, $decidedBy, $note ?? 'access-review: revoca reviewer');
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
     * Un item la cui sorgente non è più registrata non è revocabile: resta `pending`, viene
     * auditato come orfano e NON entra nel conteggio dei processati.
     *
     * @return int numero di item pending processati
     */
    public function close(ReviewCampaign $campaign): int
    {
        // IAM-17: TOCTOU. Lock the campaign row and re-check status UNDER the lock (mirroring cancel()), so
        // two concurrent close()s — or a close racing a cancel — cannot both pass the guard and double-apply
        // on_unconfirmed. The per-item locks below still protect against a reviewer deciding an item mid-close.
        return DB::transaction(function () use ($campaign): int {
            $locked = ReviewCampaign::query()->whereKey($campaign->id)->lockForUpdate()->first();
            $state = $locked->status ?? 'inesistente';
            // Chiudibile solo da running: non si chiude una draft né si ri-chiude una completed.
            if ($locked === null || $state !== 'running') {
                throw new \RuntimeException("Campagna {$campaign->id} in stato {$state}: non chiudibile (attesa: running).");
            }

            $action = $locked->on_unconfirmed;
            $processed = 0;

            /** @var Collection<int, ReviewItem> $pending */
            $pending = $locked->items()->where('decision', 'pending')->get();
            foreach ($pending as $item) {
                // Stessa garanzia di decide(): lock + ricontrollo pending, così un reviewer che decide
                // mentre la campagna si chiude non viene sovrascritto (no doppia azione sul grant).
                try {
                    DB::transaction(function () use ($item, $action): void {
                        $lockedItem = ReviewItem::query()->whereKey($item->id)->lockForUpdate()->first();
                        if ($lockedItem === null || $lockedItem->decision !== 'pending') {
                            return;
                        }

                        if ($action === 'keep') {
                            $lockedItem->forceFill([
                                'decision' => 'approved',
                                'decided_at' => now(),
                                'decided_by' => 'system:access-review',
                                'note' => 'on_unconfirmed=keep',
                            ])->save();

                            return;
                        }

                        // revoke | suspend (fail-closed): qualunque azione diversa da keep rimuove l'accesso.
                        // Se la sorgente non è più registrata, l'accesso NON è revocabile: l'item resta
                        // pending. Marcarlo `revoked` senza aver revocato nulla falsificherebbe l'evidenza
                        // — un auditor leggerebbe una revoca che non è mai avvenuta.
                        $this->revokeReviewable($lockedItem, 'system:access-review', "on_unconfirmed={$action}");
                        $lockedItem->forceFill([
                            'decision' => 'revoked',
                            'decided_at' => now(),
                            'decided_by' => 'system:access-review',
                            'note' => "on_unconfirmed={$action}",
                        ])->save();
                    });
                    $processed++;
                } catch (UnknownReviewableSource $e) {
                    // Un item orfano (modulo che lo aveva creato non più installato) non blocca la
                    // chiusura degli altri: resta pending, ed è tracciato perché qualcuno lo veda.
                    $this->recordOrphan($item, $e);
                }
            }

            $locked->forceFill(['status' => 'completed', 'closed_at' => now()])->save();

            return $processed;
        });
    }

    /**
     * Annulla una campagna ancora aperta (draft o running) SENZA applicare on_unconfirmed: nessun grant
     * viene toccato e gli item restano come sono. È una terminazione soft — non un hard-delete: la storia
     * della campagna e dei suoi item resta consultabile (invariante IGA: niente cancellazione di evidenze).
     * Una campagna completed/expired/cancelled non è ri-annullabile (fail-closed).
     */
    public function cancel(ReviewCampaign $campaign): void
    {
        // Transazione + lock di riga + ricontrollo dello stato SOTTO il lock: due transizioni concorrenti
        // sulla stessa campagna non possono entrambe passare il guard (no last-write-wins sullo stato).
        DB::transaction(function () use ($campaign): void {
            $locked = ReviewCampaign::query()->whereKey($campaign->id)->lockForUpdate()->first();
            $state = $locked->status ?? 'inesistente';
            if ($locked === null || !in_array($state, ['draft', 'running'], true)) {
                throw new \RuntimeException("Campagna {$campaign->id} in stato {$state}: non annullabile.");
            }

            $locked->forceFill(['status' => 'cancelled', 'closed_at' => now()])->save();
        });
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

    /**
     * Revoca l'accesso certificato, delegando alla sorgente che lo possiede: solo lei conosce
     * l'invariante del proprio dominio (idempotenza, eventi, `event_type` d'audit).
     *
     * @throws UnknownReviewableSource quando il tipo non è (più) registrato
     */
    private function revokeReviewable(ReviewItem $item, string $by, string $reason): void
    {
        $source = $this->registry()->for($item->reviewable_type);
        if ($source === null) {
            throw new UnknownReviewableSource($item->reviewable_type, $item->id);
        }

        $source->revoke($item->reviewable_id, $by, $reason, [
            'campaign_id' => $item->campaign_id,
            'review_item_id' => $item->id,
        ]);
    }

    /**
     * Le sorgenti incluse nella campagna.
     *
     * Default deliberato: **solo i grant**. Uno `scope_json.reviewable_types` assente significa
     * "come si è sempre comportata questa campagna" — installare un modulo che registra una nuova
     * sorgente non deve far comparire accessi inattesi dentro campagne già pianificate. Le altre
     * sorgenti si includono esplicitamente.
     *
     * @return list<ReviewableSource>
     */
    private function sourcesFor(ReviewCampaign $campaign): array
    {
        $requested = GrantReviewableSource::stringList($campaign->scope_json['reviewable_types'] ?? null);
        if ($requested === []) {
            $requested = [GrantReviewableSource::TYPE];
        }

        $out = [];
        foreach ($requested as $type) {
            $source = $this->registry()->for($type);
            // Un tipo richiesto ma non registrato si ignora in apertura (non c'è inventario da
            // leggere). Fallire l'apertura dell'intera campagna per un modulo assente sarebbe
            // peggio: le altre sorgenti resterebbero non certificate.
            if ($source !== null) {
                $out[] = $source;
            }
        }

        return $out;
    }

    private function registry(): ReviewableRegistry
    {
        return $this->registry ?? app(ReviewableRegistry::class);
    }

    private function recordOrphan(ReviewItem $item, UnknownReviewableSource $e): void
    {
        ($this->audit ?? app(AuditRecorder::class))->record([
            'stream' => 'governance',
            'event_type' => 'iam.access_review.item_unrevocable',
            'target_type' => 'review_item',
            'target_id' => $item->id,
            'metadata_json' => [
                'campaign_id' => $item->campaign_id,
                'reviewable_type' => $item->reviewable_type,
                'reviewable_id' => $item->reviewable_id,
                'reason' => $e->getMessage(),
            ],
        ]);
    }
}
