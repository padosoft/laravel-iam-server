<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Governance\Reviews\Reviewable;

use Padosoft\Iam\Domain\Governance\Reviews\Models\ReviewCampaign;

/**
 * Una categoria di accessi certificabili in una access review (doc 14 §3).
 *
 * Esiste perché l'IGA non deve sapere COSA sta certificando: i grant RBAC/ABAC sono la sorgente
 * built-in, ma un modulo opzionale (es. `laravel-iam-agents` con le delegation grant) ne registra
 * la propria senza che il core lo conosca. Il core orchestra la campagna; la sorgente sa leggere
 * il proprio inventario e sa revocare.
 *
 * La revoca appartiene alla sorgente, non all'engine: solo lei conosce l'invariante del proprio
 * dominio (idempotenza, eventi, audit con il proprio `event_type`). L'engine le passa il contesto
 * della campagna perché finisca nei metadata.
 */
interface ReviewableSource
{
    /**
     * Discriminante persistito in `iam_review_items.reviewable_type`. Stabile nel tempo:
     * cambiarlo orfanerebbe gli item storici, che sono evidenza d'audit.
     */
    public function type(): string;

    /** Etichetta leggibile, per l'admin UI (es. "Delegation grants"). */
    public function label(): string;

    /**
     * Gli accessi ATTIVI che ricadono nello scope della campagna, con reviewer e segnali già risolti.
     *
     * @return iterable<ReviewableRef>
     */
    public function scoped(ReviewCampaign $campaign): iterable;

    /**
     * Revoca l'accesso. DEVE essere idempotente e auditare per conto proprio.
     *
     * @param  array<string, mixed>  $context  campaign_id / review_item_id, da propagare nei metadata
     * @return bool `false` quando non c'era nulla da revocare (già revocato o sparito): l'item resta
     *              comunque certificabile come `revoked`, perché l'accesso di fatto non esiste più.
     */
    public function revoke(string $id, string $by, string $reason, array $context = []): bool;

    /**
     * Campi di riepilogo per l'Admin API, in blocco (l'admin lista N item: una query, non N).
     *
     * @param  list<string>  $ids
     * @return array<string, array<string, mixed>> id => campi; un id sconosciuto va omesso
     */
    public function describeMany(array $ids): array;
}
