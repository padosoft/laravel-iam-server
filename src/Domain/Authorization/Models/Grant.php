<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Authorization\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Padosoft\Iam\Domain\Organizations\Models\Organization;

/**
 * Grant canonico (riconcilia doc 09 §9 e doc 14 §2). IGA-ready by design.
 *
 * @property string $id
 * @property string $subject_type
 * @property string $subject_id
 * @property string $privilege_type
 * @property string $privilege_key
 * @property string $effect
 * @property bool $is_privileged
 * @property bool $activation_required
 */
final class Grant extends Model
{
    use HasUlids;

    protected $table = 'iam_grants';

    protected $guarded = [];

    /** @var array<string, mixed> */
    protected $attributes = [
        'effect' => 'permit',
        'is_privileged' => false,
        'activation_required' => false,
    ];

    protected $casts = [
        'conditions_json' => 'array',
        'is_privileged' => 'bool',
        'activation_required' => 'bool',
        'valid_from' => 'datetime',
        'valid_until' => 'datetime',
        'last_used_at' => 'datetime',
        'revoked_at' => 'datetime',
    ];

    /** @return BelongsTo<Organization, $this> */
    public function organization(): BelongsTo
    {
        return $this->belongsTo(Organization::class, 'organization_id');
    }

    /**
     * Grant attivi (non revocati e dentro la finestra di validità).
     *
     * @param  Builder<Grant>  $query
     */
    public function scopeActive(Builder $query): void
    {
        $query->whereNull('revoked_at')
            ->where(function (Builder $q): void {
                $q->whereNull('valid_from')->orWhere('valid_from', '<=', now());
            })
            ->where(function (Builder $q): void {
                $q->whereNull('valid_until')->orWhere('valid_until', '>=', now());
            });
    }
}
