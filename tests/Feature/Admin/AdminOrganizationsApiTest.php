<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Padosoft\Iam\Domain\Organizations\Models\Organization;

uses(RefreshDatabase::class);

// bindTestResolver()/grantAdmin() are global helpers (AdminUsersApiTest.php).
beforeEach(fn () => bindTestResolver());

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
