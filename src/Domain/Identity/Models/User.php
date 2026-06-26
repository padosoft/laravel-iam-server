<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Identity\Models;

use Illuminate\Auth\Authenticatable as AuthenticatableTrait;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Support\Carbon;
use Padosoft\Iam\Domain\Authorization\Models\Grant;
use Padosoft\Iam\Domain\Organizations\Models\Membership;

/**
 * Utente IAM (doc 10 §7). Identità globale; appartiene a N org via membership.
 *
 * È Authenticatable per integrarsi con il guard/Fortify e con il flusso OAuth /authorize.
 * Le credenziali (password/passkey/totp) NON vivono qui ma in iam_identities/Fortify: una
 * UserProvider dedicata (M5.4/deploy) le risolve. `getAuthIdentifier()` ritorna l'ULID.
 *
 * @property string $id
 * @property string $status
 * @property string|null $email
 * @property string|null $name
 * @property Carbon|null $email_verified_at
 */
final class User extends Model implements Authenticatable
{
    use AuthenticatableTrait;
    use HasUlids;

    protected $table = 'iam_users';

    /** @var list<string> */
    protected $fillable = [
        // 'status' NON è fillable: si imposta solo via changeStatus() per garantire l'audit trail.
        'email', 'email_verified_at', 'name', 'primary_identity_id',
    ];

    /** @var array<string, mixed> */
    protected $attributes = [
        'status' => 'active',
    ];

    protected $casts = [
        'email_verified_at' => 'datetime',
    ];

    /** @return HasMany<Membership, $this> */
    public function memberships(): HasMany
    {
        return $this->hasMany(Membership::class, 'user_id');
    }

    /** @return HasMany<UserStatusChange, $this> */
    public function statusChanges(): HasMany
    {
        return $this->hasMany(UserStatusChange::class, 'user_id');
    }

    /**
     * Grant in cui il subject è questo utente.
     *
     * @return HasMany<Grant, $this>
     */
    public function grants(): HasMany
    {
        return $this->hasMany(Grant::class, 'subject_id')->where('subject_type', 'user');
    }

    /**
     * Cambia lo stato dell'utente — unico modo per valorizzare `status`.
     * Scrive atomicamente il record UserStatusChange per rispettare l'invariante #4 (audit per ogni mutazione).
     */
    public function changeStatus(string $to, string $actor, string $reason = '', string $source = 'manual'): void
    {
        $from = $this->status;
        $this->forceFill(['status' => $to])->save();
        $this->statusChanges()->create([
            'from_status' => $from,
            'to_status' => $to,
            'actor_ref' => $actor,
            'reason' => $reason !== '' ? $reason : null,
            'source' => $source,
            'occurred_at' => now(),
        ]);
    }
}
