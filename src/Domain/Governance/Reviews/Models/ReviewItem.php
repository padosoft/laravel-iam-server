<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Governance\Reviews\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;
use Padosoft\Iam\Domain\Authorization\Models\Grant;

/**
 * Singolo accesso (grant) da certificare in una campagna (doc 14 §3). Porta lo snapshot dei segnali
 * smart che guidano il reviewer (signals_json) e l'esito (decision). La decisione si scrive solo via
 * CampaignEngine (decided_at/decided_by NON fillable) → storia immutabile e auditabile.
 *
 * @property string $id
 * @property string $campaign_id
 * @property string $grant_id
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

    /** @var list<string> */
    protected $fillable = [
        'campaign_id', 'grant_id', 'reviewer_subject', 'signals_json',
        // decision/decided_at/decided_by/note NON sono fillable: li scrive solo il CampaignEngine.
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

    /** @return BelongsTo<Grant, $this> */
    public function grant(): BelongsTo
    {
        return $this->belongsTo(Grant::class, 'grant_id');
    }
}
