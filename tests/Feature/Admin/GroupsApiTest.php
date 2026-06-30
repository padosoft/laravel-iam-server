<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Iam\Domain\Authorization\Models\Grant;
use Padosoft\Iam\Domain\Groups\Models\Group;
use Padosoft\Iam\Domain\Groups\Models\GroupMember;
use Padosoft\Iam\Domain\Organizations\Models\Organization;
use Padosoft\Iam\Http\Admin\Support\AdminActorResolver;
use Padosoft\Iam\Http\Admin\Support\AdminContext;

uses(RefreshDatabase::class);

// Self-contained (niente helper globali condivisi fra file): resolver di test via X-Test-Auth, org-bound.
function groupsBind(?string $org): void
{
    app()->bind(AdminActorResolver::class, fn (): AdminActorResolver => new class($org) implements AdminActorResolver
    {
        public function __construct(private ?string $org) {}

        public function resolve(Request $request): ?AdminContext
        {
            $id = $request->headers->get('X-Test-Auth');

            return is_string($id) && $id !== '' ? new AdminContext(new SubjectRef('user', $id), $this->org) : null;
        }
    });
}

/** @param list<string> $permissions */
function groupsGrant(string $subjectId, array $permissions): void
{
    foreach ($permissions as $perm) {
        Grant::create([
            'subject_type' => 'user', 'subject_id' => $subjectId,
            'privilege_type' => 'permission', 'privilege_key' => $perm,
        ]);
    }
}

function groupsOrg(string $key = 'g'): string
{
    return Organization::create(['key' => $key, 'name' => strtoupper($key)])->id;
}

it('rifiuta 403 fail-closed senza permesso', function () {
    groupsBind(groupsOrg());
    $this->getJson('/api/iam/v1/groups', ['X-Test-Auth' => 'adm'])->assertStatus(403);
});

it('CRUD completo di un gruppo (create, show, list, patch, delete)', function () {
    $org = groupsOrg();
    groupsBind($org);
    groupsGrant('adm', ['iam:groups.read', 'iam:groups.manage']);
    $h = ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'g1'];

    $create = $this->postJson('/api/iam/v1/groups', ['key' => 'eng', 'name' => 'Engineering'], $h);
    $create->assertStatus(201)->assertJsonPath('data.key', 'eng');
    $id = $create->json('data.id');

    $this->getJson("/api/iam/v1/groups/{$id}", ['X-Test-Auth' => 'adm'])->assertOk()->assertJsonPath('data.name', 'Engineering');
    $this->getJson('/api/iam/v1/groups', ['X-Test-Auth' => 'adm'])->assertOk()->assertJsonStructure(['data', 'next_cursor']);

    $this->patchJson("/api/iam/v1/groups/{$id}", ['name' => 'Eng Team'], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'g2'])
        ->assertOk()->assertJsonPath('data.name', 'Eng Team');

    $this->deleteJson("/api/iam/v1/groups/{$id}", [], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'g3'])
        ->assertOk()->assertJsonPath('data.revoked', true);
    expect(Group::query()->find($id)->revoked_at)->not->toBeNull();
});

it('una key duplicata nella stessa org è 409', function () {
    $org = groupsOrg();
    groupsBind($org);
    groupsGrant('adm', ['iam:groups.manage']);
    Group::create(['organization_id' => $org, 'key' => 'eng', 'name' => 'Eng']);

    $this->postJson('/api/iam/v1/groups', ['key' => 'eng', 'name' => 'Dup'], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'dup'])
        ->assertStatus(409);
});

it('una mutazione senza Idempotency-Key è 422', function () {
    groupsBind(groupsOrg());
    groupsGrant('adm', ['iam:groups.manage']);

    $this->postJson('/api/iam/v1/groups', ['key' => 'eng', 'name' => 'Eng'], ['X-Test-Auth' => 'adm'])
        ->assertStatus(422);
});

it('aggiunge e rimuove membri (con dedup idempotente)', function () {
    $org = groupsOrg();
    groupsBind($org);
    groupsGrant('adm', ['iam:groups.read', 'iam:groups.manage']);
    $group = Group::create(['organization_id' => $org, 'key' => 'eng', 'name' => 'Eng']);
    $auth = ['X-Test-Auth' => 'adm'];

    $this->postJson("/api/iam/v1/groups/{$group->id}/members", ['member_type' => 'user', 'member_id' => 'usr_1'], $auth + ['Idempotency-Key' => 'm1'])
        ->assertStatus(201)->assertJsonPath('data.member_id', 'usr_1');
    // stessa membership → nessun duplicato (insertOrIgnore sull'unique)
    $this->postJson("/api/iam/v1/groups/{$group->id}/members", ['member_type' => 'user', 'member_id' => 'usr_1'], $auth + ['Idempotency-Key' => 'm2'])
        ->assertStatus(201);
    expect(GroupMember::query()->where('group_id', $group->id)->count())->toBe(1);

    $this->getJson("/api/iam/v1/groups/{$group->id}/members", $auth)->assertOk()->assertJsonStructure(['data', 'next_cursor']);

    $this->deleteJson("/api/iam/v1/groups/{$group->id}/members", ['member_type' => 'user', 'member_id' => 'usr_1'], $auth + ['Idempotency-Key' => 'm3'])
        ->assertOk()->assertJsonPath('data.removed', true);
    expect(GroupMember::query()->where('group_id', $group->id)->count())->toBe(0);
});

it('un member_type non valido è 422', function () {
    $org = groupsOrg();
    groupsBind($org);
    groupsGrant('adm', ['iam:groups.manage']);
    $group = Group::create(['organization_id' => $org, 'key' => 'eng', 'name' => 'Eng']);

    $this->postJson("/api/iam/v1/groups/{$group->id}/members", ['member_type' => 'robot', 'member_id' => 'x'], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'bad'])
        ->assertStatus(422);
});

it('un admin di un\'org non vede un gruppo di un altro tenant (404, no enumerazione)', function () {
    $orgA = groupsOrg('a');
    $orgB = groupsOrg('b');
    $foreign = Group::create(['organization_id' => $orgB, 'key' => 'fin', 'name' => 'Finance']);

    groupsBind($orgA);
    groupsGrant('adm', ['iam:groups.read']);

    $this->getJson("/api/iam/v1/groups/{$foreign->id}", ['X-Test-Auth' => 'adm'])->assertStatus(404);
});
