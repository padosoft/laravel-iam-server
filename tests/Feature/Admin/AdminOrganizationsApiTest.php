<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Iam\Domain\Organizations\Models\Organization;
use Padosoft\Iam\Http\Admin\Support\AdminActorResolver;
use Padosoft\Iam\Http\Admin\Support\AdminContext;

uses(RefreshDatabase::class);

// bindTestResolver()/grantAdmin() are global helpers (AdminUsersApiTest.php).
beforeEach(fn () => bindTestResolver());

// Bind an actor resolver constrained to a specific tenant org (mirrors AdminUsersApiTest).
function bindTenantResolver(string $orgId): void
{
    app()->bind(AdminActorResolver::class, fn () => new class($orgId) implements AdminActorResolver
    {
        public function __construct(private readonly string $orgId) {}

        public function resolve(Request $request): ?AdminContext
        {
            $id = $request->headers->get('X-Test-Auth');

            return is_string($id) && $id !== '' ? new AdminContext(new SubjectRef('user', $id), $this->orgId) : null;
        }
    });
}

it('organizations: crea, elenca, mostra, aggiorna e sospende', function () {
    grantAdmin('adm', ['iam:organizations.read', 'iam:organizations.manage']);

    $create = $this->postJson('/api/iam/v1/organizations', ['key' => 'acme', 'name' => 'Acme Inc'], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'o1']);
    $create->assertStatus(201)->assertJsonPath('data.key', 'acme')->assertJsonPath('data.status', 'active');
    $id = $create->json('data.id');

    $this->getJson('/api/iam/v1/organizations', ['X-Test-Auth' => 'adm'])->assertOk()->assertJsonPath('data.0.key', 'acme');
    $this->getJson('/api/iam/v1/organizations/acme', ['X-Test-Auth' => 'adm'])->assertOk()->assertJsonPath('data.name', 'Acme Inc');

    $this->patchJson('/api/iam/v1/organizations/acme', ['name' => 'Acme Corp'], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'o2'])
        ->assertOk()->assertJsonPath('data.name', 'Acme Corp');

    $this->deleteJson('/api/iam/v1/organizations/acme', [], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'o3'])
        ->assertOk()->assertJsonPath('data.status', 'suspended');
    expect(Organization::query()->find($id)?->status)->toBe('suspended');
});

it('organizations: key duplicata è 409', function () {
    grantAdmin('adm', ['iam:organizations.manage']);
    Organization::query()->create(['key' => 'dup', 'name' => 'One']);

    $this->postJson('/api/iam/v1/organizations', ['key' => 'dup', 'name' => 'Two'], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'o4'])
        ->assertStatus(409);
});

it('organizations: rinomina la key (safe internamente) e 409 su key già esistente', function () {
    grantAdmin('adm', ['iam:organizations.manage', 'iam:organizations.read']);
    $org = Organization::query()->create(['key' => 'old', 'name' => 'Org']);
    Organization::query()->create(['key' => 'taken', 'name' => 'Other']);

    $this->patchJson('/api/iam/v1/organizations/old', ['key' => 'new'], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'k1'])
        ->assertOk()->assertJsonPath('data.key', 'new');
    expect(Organization::query()->find($org->id)?->key)->toBe('new');

    $this->patchJson('/api/iam/v1/organizations/new', ['key' => 'taken'], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'k2'])
        ->assertStatus(409);
});

it('organizations: senza permesso è 403', function () {
    grantAdmin('adm', ['iam:groups.read']);
    $this->getJson('/api/iam/v1/organizations', ['X-Test-Auth' => 'adm'])->assertStatus(403);
});

it('groups: un admin globale crea un gruppo passando organization_id (per key)', function () {
    grantAdmin('adm', ['iam:groups.manage', 'iam:groups.read']);
    $org = Organization::query()->create(['key' => 'acme', 'name' => 'Acme']);

    $res = $this->postJson('/api/iam/v1/groups', ['key' => 'eng', 'name' => 'Engineering', 'organization_id' => 'acme'], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'g1']);

    $res->assertStatus(201)->assertJsonPath('data.key', 'eng')->assertJsonPath('data.organization_id', $org->id);
});

it('groups: admin globale senza organization_id è 422', function () {
    grantAdmin('adm', ['iam:groups.manage']);
    $this->postJson('/api/iam/v1/groups', ['key' => 'eng', 'name' => 'Engineering'], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'g2'])
        ->assertStatus(422);
});

it('groups: organization_id inesistente è 422', function () {
    grantAdmin('adm', ['iam:groups.manage']);
    $this->postJson('/api/iam/v1/groups', ['key' => 'eng', 'name' => 'Engineering', 'organization_id' => 'nope'], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'g3'])
        ->assertStatus(422);
});

it('organizations: un admin vincolato a un tenant vede solo la sua org e 404 sulle altre', function () {
    $mine = Organization::query()->create(['key' => 'mine', 'name' => 'Mine']);
    Organization::query()->create(['key' => 'other', 'name' => 'Other']);
    bindTenantResolver($mine->id);
    grantAdmin('adm', ['iam:organizations.read', 'iam:organizations.manage']);

    $list = $this->getJson('/api/iam/v1/organizations', ['X-Test-Auth' => 'adm'])->assertOk();
    expect($list->json('data'))->toHaveCount(1)->and($list->json('data.0.key'))->toBe('mine');

    // Cross-tenant read/mutate → 404 (no enumeration, no cross-tenant suspend).
    $this->getJson('/api/iam/v1/organizations/other', ['X-Test-Auth' => 'adm'])->assertStatus(404);
    $this->patchJson('/api/iam/v1/organizations/other', ['name' => 'X'], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'i1'])->assertStatus(404);
    $this->deleteJson('/api/iam/v1/organizations/other', [], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'i2'])->assertStatus(404);
});

it('groups: un tenant admin ignora un organization_id nel body (crea nella SUA org)', function () {
    $mine = Organization::query()->create(['key' => 'mine', 'name' => 'Mine']);
    Organization::query()->create(['key' => 'other', 'name' => 'Other']);
    bindTenantResolver($mine->id);
    grantAdmin('adm', ['iam:groups.manage']);

    $res = $this->postJson('/api/iam/v1/groups', ['key' => 'eng', 'name' => 'Eng', 'organization_id' => 'other'], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'g9']);

    $res->assertStatus(201)->assertJsonPath('data.organization_id', $mine->id); // context org, NOT the body 'other'
});
