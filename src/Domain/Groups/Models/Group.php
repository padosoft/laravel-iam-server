<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Groups\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Support\Carbon;
use Padosoft\Iam\Domain\Organizations\Models\Organization;

/**
 * Gruppo first-class (doc 19 §3): soggetto di grant e di tuple ReBAC (nesting con M16). `key` è lo slug
 * stabile, unico per organization. `revoked_at` non è mass-assignable: si imposta solo via revoke()
 * (simmetrico a Grant/Relation), così un soft-delete non avviene per mass-assignment.
 *
 * @property string $id
 * @property string $organization_id
 * @property string $key
 * @property string $name
 * @property string $source
 * @property Carbon|null $revoked_at
 */
final class Group extends Model
{
    use HasUlids;

    protected $table = 'iam_groups';

    /** @var list<string> revoked_at fuori da fillable: si imposta solo via revoke(). */
    protected $fillable = ['organization_id', 'key', 'name', 'source'];

    /** @var array<string, mixed> */
    protected $attributes = [
        'source' => 'manual',
    ];

    protected $casts = [
        'revoked_at' => 'datetime',
    ];

    /** @return BelongsTo<Organization, $this> */
    public function organization(): BelongsTo
    {
        return $this->belongsTo(Organization::class, 'organization_id');
    }

    /** @return HasMany<GroupMember, $this> */
    public function members(): HasMany
    {
        return $this->hasMany(GroupMember::class, 'group_id');
    }

    /** Revoca (soft) il gruppo — unico modo per valorizzare revoked_at. */
    public function revoke(): void
    {
        $this->forceFill(['revoked_at' => now()])->save();
    }

    /**
     * Gruppi ATTIVI: non revocati. Fail-closed by default.
     *
     * @param  Builder<Group>  $query
     */
    public function scopeActive(Builder $query): void
    {
        $query->whereNull('revoked_at');
    }
}
