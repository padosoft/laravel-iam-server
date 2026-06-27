<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Governance\Reviews\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Support\Carbon;

/**
 * Campagna di Access Review (doc 14 §3). Definisce COSA certificare (scope_json), CHI deve farlo
 * (reviewer_strategy) ed entro QUANDO (due_at), e cosa fare del non-confermato (on_unconfirmed).
 * Lifecycle: draft → running (open) → completed (close) | expired.
 *
 * @property string $id
 * @property string|null $organization_id
 * @property string $name
 * @property array<string, mixed>|null $scope_json
 * @property string $reviewer_strategy
 * @property Carbon|null $due_at
 * @property string $status
 * @property string $on_unconfirmed
 */
final class ReviewCampaign extends Model
{
    use HasUlids;

    protected $table = 'iam_review_campaigns';

    /** @var list<string> */
    protected $fillable = [
        'organization_id', 'name', 'scope_json',
        'reviewer_strategy', 'due_at', 'on_unconfirmed', 'created_by',
        // status/opened_at/closed_at NON sono fillable: li muove solo il CampaignEngine.
    ];

    /** @var array<string, mixed> */
    protected $attributes = [
        'status' => 'draft',
        'reviewer_strategy' => 'named',
        'on_unconfirmed' => 'revoke',
    ];

    protected $casts = [
        'scope_json' => 'array',
        'due_at' => 'datetime',
        'opened_at' => 'datetime',
        'closed_at' => 'datetime',
    ];

    /** @return HasMany<ReviewItem, $this> */
    public function items(): HasMany
    {
        return $this->hasMany(ReviewItem::class, 'campaign_id');
    }
}
