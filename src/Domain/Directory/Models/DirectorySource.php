<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Directory\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;
use Padosoft\Iam\Domain\Organizations\Models\Organization;

/**
 * Sorgente directory LDAP/AD (doc 19 §5). Il server possiede la CONFIG; il modulo `-directory` la
 * consuma per sync/JIT. `bind_secret_encrypted` è l'envelope SecretCipher (M3): fuori da fillable e mai
 * restituito in chiaro (write-only). `last_sync_*` non sono fillable: li aggiorna solo il flusso di sync.
 *
 * @property string $id
 * @property string|null $organization_id
 * @property string $key
 * @property string $name
 * @property string $type
 * @property string $host
 * @property string $base_dn
 * @property string|null $bind_dn
 * @property array{ciphertext: string, wrapped_dek: string|null, key_id: string, key_version: int, scope: string|null}|null $bind_secret_encrypted
 * @property array<array-key, mixed>|null $filters
 * @property string|null $group_mapping_ref
 * @property string $sync_mode
 * @property string $status
 * @property string|null $last_sync_status
 * @property Carbon|null $last_sync_at
 */
final class DirectorySource extends Model
{
    use HasUlids;

    protected $table = 'iam_directory_sources';

    /** @var list<string> bind_secret_encrypted/last_sync_* fuori da fillable (write-only / solo sync). */
    protected $fillable = [
        'organization_id', 'key', 'name', 'type', 'host', 'base_dn', 'bind_dn',
        'filters', 'group_mapping_ref', 'sync_mode', 'status',
    ];

    /** @var array<string, mixed> */
    protected $attributes = [
        'type' => 'ldap',
        'sync_mode' => 'jit',
        'status' => 'active',
    ];

    protected $casts = [
        'bind_secret_encrypted' => 'array',
        'filters' => 'array',
        'last_sync_at' => 'datetime',
    ];

    /** @return BelongsTo<Organization, $this> */
    public function organization(): BelongsTo
    {
        return $this->belongsTo(Organization::class, 'organization_id');
    }
}
