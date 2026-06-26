<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Organizations\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Padosoft\Iam\Domain\Identity\Models\User;

/**
 * Appartenenza di un utente a un'organizzazione (doc 09 §9).
 *
 * @property string $id
 * @property string $status
 */
final class Membership extends Model
{
    use HasUlids;

    protected $table = 'iam_memberships';

    protected $guarded = [];

    protected $casts = [
        'joined_at' => 'datetime',
        'removed_at' => 'datetime',
    ];

    /** @return BelongsTo<User, $this> */
    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class, 'user_id');
    }

    /** @return BelongsTo<Organization, $this> */
    public function organization(): BelongsTo
    {
        return $this->belongsTo(Organization::class, 'organization_id');
    }
}
