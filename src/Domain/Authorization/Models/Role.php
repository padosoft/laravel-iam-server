<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Authorization\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Support\Carbon;

/**
 * Ruolo del catalogo (doc 09 §9). `full_key` = app_key:key, immutabile (ADR-0019).
 *
 * @property string $id
 * @property string $app_key
 * @property string $key
 * @property string $full_key
 * @property string|null $label
 * @property bool $is_privileged
 * @property bool $self_requestable
 * @property array<string, mixed>|null $request_json
 * @property Carbon|null $deprecated_at
 */
final class Role extends Model
{
    use HasUlids;

    protected $table = 'iam_roles';

    /** @var list<string> */
    protected $fillable = [
        'app_key', 'key', 'full_key', 'label', 'is_privileged',
        'self_requestable', 'request_json', 'deprecated_at',
    ];

    /** @var array<string, mixed> */
    protected $attributes = [
        'is_privileged' => false,
        'self_requestable' => false,
    ];

    protected $casts = [
        'is_privileged' => 'bool',
        'self_requestable' => 'bool',
        'request_json' => 'array',
        'deprecated_at' => 'datetime',
    ];

    /** @return BelongsToMany<Permission, $this> */
    public function permissions(): BelongsToMany
    {
        return $this->belongsToMany(Permission::class, 'iam_role_permissions', 'role_id', 'permission_id');
    }
}
