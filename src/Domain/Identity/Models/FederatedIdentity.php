<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Identity\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * Identità federata (doc 10 §5/§7). Risolta da (provider_id, provider_subject) — UNICO —, MAI
 * dalla sola email. `status`: linked | pending (conflitto da risolvere con step-up/approval).
 *
 * @property string $id
 * @property string|null $user_id
 * @property string $provider_id
 * @property string $provider_subject
 * @property string $status
 * @property string|null $email
 * @property bool $email_verified
 * @property string|null $display_name
 * @property string|null $pending_reason
 * @property Carbon|null $linked_at
 * @property Carbon|null $last_login_at
 * @property Carbon|null $revoked_at
 */
final class FederatedIdentity extends Model
{
    use HasUlids;

    protected $table = 'iam_federated_identities';

    /** @var list<string> user_id/status/linked_at fuori da fillable: li gestisce l'AccountLinker. */
    protected $fillable = [
        'provider_id', 'provider_subject', 'email', 'email_verified', 'display_name', 'raw_profile_encrypted',
    ];

    /** @var array<string, mixed> */
    protected $attributes = ['status' => 'linked', 'email_verified' => false];

    protected $casts = [
        'email_verified' => 'boolean',
        'linked_at' => 'datetime',
        'last_login_at' => 'datetime',
        'revoked_at' => 'datetime',
    ];
}
