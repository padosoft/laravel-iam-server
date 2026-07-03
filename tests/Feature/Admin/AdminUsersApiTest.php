<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Iam\Domain\Audit\Models\AuditEvent;
use Padosoft\Iam\Domain\Authorization\Models\Grant;
use Padosoft\Iam\Domain\Authorization\Models\Permission;
use Padosoft\Iam\Domain\Authorization\Models\Role;
use Padosoft\Iam\Domain\Identity\Models\User;
use Padosoft\Iam\Http\Admin\Support\AdminActorResolver;
use Padosoft\Iam\Http\Admin\Support\AdminContext;

uses(RefreshDatabase::class);

/**
 * Resolver di test: autentica se presente l'header `X-Test-Auth: <userId>`, così i test esercitano
 * l'intera catena (auth → permesso PDP → idempotency → audit) senza mintare JWT veri.
 */
function bindTestResolver(): void
{
    app()->bind(AdminActorResolver::class, fn (): AdminActorResolver => new class implements AdminActorResolver
    {
        public function resolve(Request $request): ?AdminContext
        {
            $id = $request->headers->get('X-Test-Auth');

            return is_string($id) && $id !== '' ? new AdminContext(new SubjectRef('user', $id)) : null;
        }
    });
}

/** Concede al soggetto i permessi indicati (grant globali) così il PDP autorizza. */
function grantAdmin(string $subjectId, array $permissions): void
{
    foreach ($permissions as $perm) {
        Grant::create([
            'subject_type' => 'user', 'subject_id' => $subjectId,
            'privilege_type' => 'permission', 'privilege_key' => $perm,
        ]);
    }
}

beforeEach(fn () => bindTestResolver());

it('rifiuta 401 senza autenticazione', function () {
    $this->getJson('/api/iam/v1/users')->assertStatus(401);
});

it('rifiuta 403 fail-closed se l\'attore non ha il permesso', function () {
    $this->getJson('/api/iam/v1/users', ['X-Test-Auth' => 'adm'])
        ->assertStatus(403);
});

it('elenca gli utenti con paginazione cursor quando autorizzato', function () {
    grantAdmin('adm', ['iam:users.read']);
    User::create(['email' => 'a@x.it']);
    User::create(['email' => 'b@x.it']);

    $res = $this->getJson('/api/iam/v1/users?limit=1', ['X-Test-Auth' => 'adm']);

    $res->assertOk()->assertJsonStructure(['data', 'next_cursor']);
    expect($res->json('data'))->toHaveCount(1)
        ->and($res->json('next_cursor'))->not->toBeNull();
});

it('mostra un utente e 404 per uno inesistente', function () {
    grantAdmin('adm', ['iam:users.read']);
    $u = User::create(['email' => 'a@x.it']);

    $this->getJson("/api/iam/v1/users/{$u->id}", ['X-Test-Auth' => 'adm'])
        ->assertOk()->assertJsonPath('data.id', $u->id);

    $this->getJson('/api/iam/v1/users/usr_missing', ['X-Test-Auth' => 'adm'])
        ->assertStatus(404)
        ->assertHeader('Content-Type', 'application/problem+json');
});

it('una mutazione senza Idempotency-Key è 422', function () {
    grantAdmin('adm', ['iam:users.manage']);
    $u = User::create(['email' => 'a@x.it']);

    $this->postJson("/api/iam/v1/users/{$u->id}/suspend", [], ['X-Test-Auth' => 'adm'])
        ->assertStatus(422);
});

it('sospende un utente, audita, ed è idempotente sul replay', function () {
    grantAdmin('adm', ['iam:users.manage']);
    $u = User::create(['email' => 'a@x.it']);
    $headers = ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'key-123'];

    $first = $this->postJson("/api/iam/v1/users/{$u->id}/suspend", ['reason' => 'policy'], $headers);
    $first->assertOk()->assertJsonPath('data.status', 'suspended');

    expect($u->fresh()->status)->toBe('suspended')
        ->and(AuditEvent::query()->where('event_type', 'iam.user.suspended')->where('target_id', $u->id)->count())->toBe(1);

    // Replay con la stessa chiave → risposta rigiocata, nessun secondo audit, nessun doppio effetto.
    $replay = $this->postJson("/api/iam/v1/users/{$u->id}/suspend", ['reason' => 'policy'], $headers);
    $replay->assertOk()->assertHeader('Idempotency-Replayed', 'true');

    expect(AuditEvent::query()->where('event_type', 'iam.user.suspended')->count())->toBe(1);
});

it('stessa Idempotency-Key con payload diverso è 422', function () {
    grantAdmin('adm', ['iam:users.manage']);
    $u = User::create(['email' => 'a@x.it']);
    $headers = ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'key-x'];

    $this->postJson("/api/iam/v1/users/{$u->id}/suspend", ['reason' => 'a'], $headers)->assertOk();
    $this->postJson("/api/iam/v1/users/{$u->id}/suspend", ['reason' => 'DIVERSO'], $headers)->assertStatus(422);
});

it('un admin vincolato a un\'org non vede un utente di un altro tenant (404, no enumerazione)', function () {
    // Resolver che vincola l'attore all'org "acme".
    app()->bind(AdminActorResolver::class, fn () => new class implements AdminActorResolver
    {
        public function resolve(Request $request): ?AdminContext
        {
            $id = $request->headers->get('X-Test-Auth');

            return is_string($id) && $id !== '' ? new AdminContext(new SubjectRef('user', $id), 'org_acme') : null;
        }
    });
    grantAdmin('adm', ['iam:users.read']);
    $outsider = User::create(['email' => 'b@other.it']); // NON membro di org_acme

    $this->getJson("/api/iam/v1/users/{$outsider->id}", ['X-Test-Auth' => 'adm'])
        ->assertStatus(404);
});

it('espone i permessi effettivi espandendo i ruoli', function () {
    grantAdmin('adm', ['iam:users.read']);
    $u = User::create(['email' => 'a@x.it']);

    $role = Role::create(['app_key' => 'warehouse', 'key' => 'op', 'full_key' => 'warehouse:op']);
    $perm = Permission::create(['app_key' => 'warehouse', 'key' => 'stock.read', 'full_key' => 'warehouse:stock.read']);
    $role->permissions()->attach($perm->id);
    Grant::create(['subject_type' => 'user', 'subject_id' => $u->id, 'privilege_type' => 'role', 'privilege_key' => 'warehouse:op']);

    $res = $this->getJson("/api/iam/v1/users/{$u->id}/effective-permissions", ['X-Test-Auth' => 'adm']);

    $res->assertOk();
    expect($res->json('data.permissions'))->toHaveKey('warehouse:stock.read');
});

it('aggiorna name/email di un utente e audita', function () {
    grantAdmin('adm', ['iam:users.manage']);
    $u = User::create(['email' => 'a@x.it', 'name' => 'Old']);

    $this->patchJson("/api/iam/v1/users/{$u->id}", ['name' => 'New', 'email' => 'new@x.it'], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'up1'])
        ->assertOk()->assertJsonPath('data.name', 'New')->assertJsonPath('data.email', 'new@x.it');

    expect($u->fresh()->email)->toBe('new@x.it')
        ->and(AuditEvent::query()->where('event_type', 'iam.user.updated')->where('target_id', $u->id)->count())->toBe(1);
});

it('update rifiuta email duplicata (422) e payload vuoto (422)', function () {
    grantAdmin('adm', ['iam:users.manage']);
    User::create(['email' => 'taken@x.it']);
    $u = User::create(['email' => 'a@x.it']);

    $this->patchJson("/api/iam/v1/users/{$u->id}", ['email' => 'taken@x.it'], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'up2'])
        ->assertStatus(422);
    $this->patchJson("/api/iam/v1/users/{$u->id}", [], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'up3'])
        ->assertStatus(422);
});

it('cerca utenti per q su name/email', function () {
    grantAdmin('adm', ['iam:users.read']);
    User::create(['email' => 'alice@x.it', 'name' => 'Alice']);
    User::create(['email' => 'bob@x.it', 'name' => 'Bob']);

    $res = $this->getJson('/api/iam/v1/users?q=alic', ['X-Test-Auth' => 'adm']);

    $res->assertOk();
    expect($res->json('data'))->toHaveCount(1)->and($res->json('data.0.email'))->toBe('alice@x.it');
});

it('la lista/dettaglio utente include i ruoli assegnati', function () {
    grantAdmin('adm', ['iam:users.read']);
    $u = User::create(['email' => 'a@x.it']);
    Grant::create(['subject_type' => 'user', 'subject_id' => $u->id, 'privilege_type' => 'role', 'privilege_key' => 'iam:iam-admin']);

    $res = $this->getJson("/api/iam/v1/users/{$u->id}", ['X-Test-Auth' => 'adm']);

    $res->assertOk();
    expect($res->json('data.roles'))->toContain('iam:iam-admin');
});

it('elenca i grant attivi di un utente e ne revoca uno (idempotente, audit una volta)', function () {
    grantAdmin('adm', ['iam:users.read', 'iam:grants.manage']);
    $u = User::create(['email' => 'a@x.it']);
    $g = Grant::create(['subject_type' => 'user', 'subject_id' => $u->id, 'privilege_type' => 'permission', 'privilege_key' => 'warehouse:stock.read']);

    $list = $this->getJson("/api/iam/v1/users/{$u->id}/grants", ['X-Test-Auth' => 'adm']);
    $list->assertOk();
    expect($list->json('data.grants'))->toHaveCount(1)->and($list->json('data.grants.0.id'))->toBe($g->id);

    $this->postJson("/api/iam/v1/grants/{$g->id}/revoke", [], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'rv1'])
        ->assertOk()->assertJsonPath('data.id', $g->id);
    // second revoke (new key) is a grant-level no-op → no second audit event
    $this->postJson("/api/iam/v1/grants/{$g->id}/revoke", [], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'rv2'])->assertOk();

    expect($g->fresh()->revoked_at)->not->toBeNull()
        ->and(AuditEvent::query()->where('event_type', 'iam.grant.revoked')->where('target_id', $g->id)->count())->toBe(1)
        ->and($this->getJson("/api/iam/v1/users/{$u->id}/grants", ['X-Test-Auth' => 'adm'])->json('data.grants'))->toHaveCount(0);
});

it('revoke di un grant richiede iam:grants.manage (403)', function () {
    grantAdmin('adm', ['iam:users.read']);
    $g = Grant::create(['subject_type' => 'user', 'subject_id' => 'u', 'privilege_type' => 'permission', 'privilege_key' => 'p']);
    $this->postJson("/api/iam/v1/grants/{$g->id}/revoke", [], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'rvx'])->assertStatus(403);
});
