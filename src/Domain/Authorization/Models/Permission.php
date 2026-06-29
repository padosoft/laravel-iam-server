<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Authorization\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;

/**
 * Permesso del catalogo (doc 09 §9). `full_key` = app_key:key, immutabile (ADR-0019).
 *
 * @property string $id
 * @property string $full_key
 * @property string $risk
 * @property bool $requires_step_up
 * @property string|null $relation
 */
final class Permission extends Model
{
    use HasUlids;

    protected $table = 'iam_permissions';

    /** @var list<string> */
    protected $fillable = [
        'app_key', 'key', 'full_key', 'resource', 'action', 'risk', 'requires_step_up', 'deprecated_at',
        // ReBAC (doc 18 §7.2): relazione richiesta su una risorsa per soddisfare il permesso (nullable).
        'relation',
    ];

    /** @var array<string, mixed> */
    protected $attributes = [
        'risk' => 'low',
        'requires_step_up' => false,
    ];

    protected $casts = [
        'requires_step_up' => 'bool',
        'deprecated_at' => 'datetime',
    ];

    /** @return BelongsToMany<Role, $this> */
    public function roles(): BelongsToMany
    {
        return $this->belongsToMany(Role::class, 'iam_role_permissions', 'permission_id', 'role_id');
    }
}
