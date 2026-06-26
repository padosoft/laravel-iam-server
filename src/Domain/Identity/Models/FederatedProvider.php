<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Identity\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;

/**
 * Provider di identità federata (doc 10 §7). Il client_secret è custodito cifrato (SecretCipher,
 * M3) e mai fillable. `auto_link_policy` governa l'auto-link via email verificata.
 *
 * @property string $id
 * @property string|null $organization_id
 * @property string $key
 * @property string $driver
 * @property string|null $client_id
 * @property string|null $client_secret_encrypted
 * @property string|null $redirect_uri
 * @property list<string>|null $scopes
 * @property array<string, mixed>|null $options
 * @property string $auto_link_policy
 * @property array<string, mixed>|null $jit_policy
 * @property string $status
 */
final class FederatedProvider extends Model
{
    use HasUlids;

    protected $table = 'iam_federated_providers';

    /** @var list<string> client_secret_encrypted fuori da fillable: si imposta via SecretCipher. */
    protected $fillable = [
        'organization_id', 'key', 'driver', 'client_id', 'redirect_uri',
        'scopes', 'options', 'auto_link_policy', 'jit_policy', 'status',
    ];

    /** @var array<string, mixed> */
    protected $attributes = [
        'auto_link_policy' => 'verified_email',
        'status' => 'active',
    ];

    protected $casts = [
        'scopes' => 'array',
        'options' => 'array',
        'jit_policy' => 'array',
    ];
}
