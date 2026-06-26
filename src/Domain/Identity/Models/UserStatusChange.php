<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Identity\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * Audit del lifecycle utente (doc 10 §7).
 *
 * @property string $id
 */
final class UserStatusChange extends Model
{
    use HasUlids;

    protected $table = 'iam_user_status_changes';

    /** @var list<string> */
    protected $fillable = [
        'user_id', 'from_status', 'to_status', 'source', 'reason', 'actor_ref', 'occurred_at',
    ];

    protected $casts = [
        'occurred_at' => 'datetime',
    ];

    /** @return BelongsTo<User, $this> */
    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class, 'user_id');
    }
}
