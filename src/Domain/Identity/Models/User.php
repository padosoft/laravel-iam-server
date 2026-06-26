<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Identity\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Padosoft\Iam\Domain\Authorization\Models\Grant;
use Padosoft\Iam\Domain\Organizations\Models\Membership;

/**
 * Utente IAM (doc 10 §7). Identità globale; appartiene a N org via membership.
 *
 * @property string $id
 * @property string $status
 * @property string|null $email
 */
final class User extends Model
{
    use HasUlids;

    protected $table = 'iam_users';

    /** @var list<string> */
    protected $fillable = [
        'status', 'email', 'email_verified_at', 'name', 'primary_identity_id',
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
}
