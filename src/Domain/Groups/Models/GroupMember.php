<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Groups\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * Membro di un gruppo (doc 19 §3). `(group_id, member_type, member_id)` è UNICO. La scrittura passa
 * sempre dal GroupMembershipService, che materializza ANCHE la tupla ReBAC `member` (single source per
 * il NativeReBacResolver::expandGroups()); mai insert diretti, altrimenti membership e nesting divergono.
 *
 * @property string $id
 * @property string $group_id
 * @property string $member_type
 * @property string $member_id
 */
final class GroupMember extends Model
{
    use HasUlids;

    protected $table = 'iam_group_members';

    /** @var list<string> */
    protected $fillable = ['group_id', 'member_type', 'member_id'];

    /** @return BelongsTo<Group, $this> */
    public function group(): BelongsTo
    {
        return $this->belongsTo(Group::class, 'group_id');
    }
}
