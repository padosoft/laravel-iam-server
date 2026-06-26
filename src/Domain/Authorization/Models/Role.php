<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Authorization\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;

/**
 * Ruolo del catalogo (doc 09 §9). `full_key` = app_key:key, immutabile (ADR-0019).
 *
 * @property string $id
 * @property string $full_key
 * @property bool $is_privileged
 */
final class Role extends Model
{
    use HasUlids;

    protected $table = 'iam_roles';

    /** @var list<string> */
    protected $fillable = [
        'app_key', 'key', 'full_key', 'label', 'is_privileged', 'deprecated_at',
    ];

    /** @var array<string, mixed> */
    protected $attributes = [
        'is_privileged' => false,
    ];

    protected $casts = [
        'is_privileged' => 'bool',
        'deprecated_at' => 'datetime',
    ];

    /** @return BelongsToMany<Permission, $this> */
    public function permissions(): BelongsToMany
    {
        return $this->belongsToMany(Permission::class, 'iam_role_permissions', 'role_id', 'permission_id');
    }
}
