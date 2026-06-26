<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Organizations\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Padosoft\Iam\Domain\Authorization\Models\Grant;

/**
 * Organizzazione / tenant (doc 09/10). Multi-tenant nativo.
 *
 * @property string $id
 * @property string $key
 * @property string $name
 */
final class Organization extends Model
{
    use HasUlids;

    protected $table = 'iam_organizations';

    /** @var list<string> */
    protected $fillable = [
        'key', 'name', 'status', 'metadata',
    ];

    /** @var array<string, mixed> */
    protected $attributes = [
        'status' => 'active',
    ];

    protected $casts = [
        'metadata' => 'array',
    ];

    /** @return HasMany<Membership, $this> */
    public function memberships(): HasMany
    {
        return $this->hasMany(Membership::class, 'organization_id');
    }

    /** @return HasMany<Grant, $this> */
    public function grants(): HasMany
    {
        return $this->hasMany(Grant::class, 'organization_id');
    }
}
