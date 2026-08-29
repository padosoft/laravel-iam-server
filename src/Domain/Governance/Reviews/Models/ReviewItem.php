<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Governance\Reviews\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;

/**
 * Singolo accesso da certificare in una campagna (doc 14 §3). Porta lo snapshot dei segnali
 * smart che guidano il reviewer (signals_json) e l'esito (decision). La decisione si scrive solo via
 * CampaignEngine (decided_at/decided_by NON fillable) → storia immutabile e auditabile.
 *
 * L'oggetto certificato è polimorfico (`reviewable_type` + `reviewable_id`): un grant RBAC/ABAC,
 * una delegation grant di `laravel-iam-agents`, o qualunque altra sorgente registrata. Non c'è una
 * relazione Eloquent perché le sorgenti vivono in pacchetti che il core non conosce: si passa dal
 * ReviewableRegistry.
 *
 * @property string $id
 * @property string $campaign_id
 * @property string $reviewable_type
 * @property string $reviewable_id
 * @property string|null $reviewer_subject
 * @property string $decision
 * @property array<string, mixed>|null $signals_json
 * @property Carbon|null $decided_at
 * @property string|null $decided_by
 * @property string|null $note
 */
final class ReviewItem extends Model
{
    use HasUlids;

    protected $table = 'iam_review_items';

    /**
     * Solo l'identità dell'item è mass-assignable. reviewer_subject/signals_json sono uno SNAPSHOT
     * immutabile scritto dal CampaignEngine in apertura (forceFill) → non alterabile dopo la creazione;
     * decision/decided_* idem (storia immutabile e auditabile).
     *
     * @var list<string>
     */
    protected $fillable = [
        'campaign_id', 'reviewable_type', 'reviewable_id',
    ];

    /** @var array<string, mixed> */
    protected $attributes = [
        'decision' => 'pending',
    ];

    protected $casts = [
        'signals_json' => 'array',
        'decided_at' => 'datetime',
    ];

    /** @return BelongsTo<ReviewCampaign, $this> */
    public function campaign(): BelongsTo
    {
        return $this->belongsTo(ReviewCampaign::class, 'campaign_id');
    }
}
