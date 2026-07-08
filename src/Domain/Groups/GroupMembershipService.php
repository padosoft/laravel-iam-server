<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Groups;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Iam\Domain\Authorization\Models\Relation;
use Padosoft\Iam\Domain\Authorization\Pdp\ResourceRef;
use Padosoft\Iam\Domain\Authorization\Relations\RelationWriter;
use Padosoft\Iam\Domain\Groups\Models\Group;
use Padosoft\Iam\Domain\Groups\Models\GroupMember;

/**
 * Ponte groups↔ReBAC (doc 19 §3). UNICO punto di scrittura delle membership: ogni add/remove scrive
 * SIA il record `iam_group_members` SIA la tupla ReBAC `member` (subject=membro, object=group:<key>)
 * via RelationWriter, così membership e nesting restano una single source che il
 * NativeReBacResolver::expandGroups() attraversa. Mai insert diretti sul model, o i due divergono.
 *
 * L'oggetto della tupla usa la `key` del gruppo (slug stabile, tenant-scoped) coerente con la
 * convenzione `group:<key>` usata dalle relation ReBAC.
 */
final class GroupMembershipService
{
    public function __construct(private readonly RelationWriter $relations) {}

    /**
     * Aggiunge (idempotente) un membro al gruppo e materializza la tupla `member`. L'insert del record
     * è ATOMICO (insertOrIgnore sull'unique (group_id, member_type, member_id)): niente TOCTOU né
     * UniqueConstraintViolation su due add concorrenti dello stesso membro.
     */
    public function addMember(Group $group, string $memberType, string $memberId, ?string $actor = null): GroupMember
    {
        // Atomico: la riga membership e la tupla ReBAC devono restare coerenti. Se la grant() fallisce
        // la transazione annulla anche l'insert → niente stato parziale (membro senza tupla `member`).
        return DB::transaction(function () use ($group, $memberType, $memberId, $actor): GroupMember {
            DB::table('iam_group_members')->insertOrIgnore([
                'id' => (string) Str::ulid(),
                'group_id' => $group->id,
                'member_type' => $memberType,
                'member_id' => $memberId,
                'created_at' => now(),
                'updated_at' => now(),
            ]);

            // Tupla ReBAC: (membro) —member→ (group:<key>). RelationWriter è idempotente (dedup identity_hash).
            $this->relations->grant(
                new SubjectRef($memberType, $memberId),
                'member',
                new ResourceRef('group', $group->key),
                null,
                $group->organization_id,
                $actor,
            );

            return GroupMember::query()
                ->where('group_id', $group->id)
                ->where('member_type', $memberType)
                ->where('member_id', $memberId)
                ->firstOrFail();
        });
    }

    /**
     * Rimuove (idempotente) il membro e revoca la tupla `member`. Ritorna true se il record esisteva.
     */
    public function removeMember(Group $group, string $memberType, string $memberId): bool
    {
        // Atomico (simmetrico ad addMember): delete della membership e revoca della tupla insieme.
        return DB::transaction(function () use ($group, $memberType, $memberId): bool {
            $deleted = GroupMember::query()
                ->where('group_id', $group->id)
                ->where('member_type', $memberType)
                ->where('member_id', $memberId)
                ->delete();

            // Revoca la tupla a prescindere (idempotente): membership e ReBAC restano coerenti anche se
            // uno dei due lati era già assente.
            $this->relations->revoke(
                new SubjectRef($memberType, $memberId),
                'member',
                new ResourceRef('group', $group->key),
                $group->organization_id,
            );

            return $deleted > 0;
        });
    }

    /**
     * @return Builder<GroupMember>
     */
    public function membersQuery(Group $group): Builder
    {
        return GroupMember::query()->where('group_id', $group->id);
    }

    /**
     * IAM-18: contenimento su delete del gruppo. Revocare (soft) il gruppo NON basta: le tuple ReBAC
     * `member` (e quelle in cui il gruppo è subject: nesting, ownership) restano attive e continuano a
     * conferire accesso a tutti i membri. Qui revochiamo OGNI tupla attiva in cui il gruppo compare come
     * subject o come object (via RelationWriter → ogni revoca è audita) e svuotiamo il ledger dei membri,
     * così un gruppo eliminato non concede più nulla.
     */
    public function revokeAllForGroup(Group $group): void
    {
        DB::transaction(function () use ($group): void {
            /** @var iterable<Relation> $tuples */
            $tuples = Relation::query()
                ->whereNull('revoked_at')
                ->where(fn (Builder $w) => $w
                    ->where(fn (Builder $s) => $s->where('subject_type', 'group')->where('subject_id', $group->key))
                    ->orWhere(fn (Builder $o) => $o->where('object_type', 'group')->where('object_id', $group->key)))
                ->when(
                    $group->organization_id === null,
                    fn (Builder $q) => $q->whereNull('organization_id'),
                    fn (Builder $q) => $q->where('organization_id', $group->organization_id),
                )
                ->get();

            foreach ($tuples as $tuple) {
                $this->relations->revoke(
                    new SubjectRef($tuple->subject_type, $tuple->subject_id),
                    $tuple->relation,
                    new ResourceRef($tuple->object_type, $tuple->object_id),
                    $tuple->organization_id,
                );
            }

            // Il ledger delle membership segue le tuple: un gruppo eliminato non ha più membri.
            GroupMember::query()->where('group_id', $group->id)->delete();
        });
    }
}
