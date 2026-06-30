<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Iam\Domain\Authorization\Models\Grant;
use Padosoft\Iam\Domain\Authorization\Models\Permission;
use Padosoft\Iam\Domain\Authorization\Models\Role;
use Padosoft\Iam\Domain\Authorization\Pdp\ResourceRef;
use Padosoft\Iam\Domain\Authorization\Relations\RelationWriter;
use Padosoft\Iam\Http\Admin\Support\AdminActorResolver;
use Padosoft\Iam\Http\Admin\Support\AdminContext;

uses(RefreshDatabase::class);

// Self-contained: resolver di test via X-Test-Auth (super admin, org null).
function wizBind(): void
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

/** @param list<string> $permissions */
function wizGrant(string $subjectId, array $permissions): void
{
    foreach ($permissions as $perm) {
        Grant::create([
            'subject_type' => 'user', 'subject_id' => $subjectId,
            'privilege_type' => 'permission', 'privilege_key' => $perm,
        ]);
    }
}

beforeEach(fn () => wizBind());

it('rifiuta 403 fail-closed senza permesso sul commit', function () {
    wizGrant('adm', ['iam:policies.read']); // ha read ma NON grants.manage
    $this->postJson('/api/iam/v1/policies-wizard/commit', [
        'subject' => ['type' => 'user', 'id' => 'usr_1'], 'privilege_type' => 'permission', 'privilege_key' => 'warehouse:stock.read',
    ], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'c0'])->assertStatus(403);
});

it('il catalogo permissions/roles è filtrabile per app', function () {
    wizGrant('adm', ['iam:policies.read']);
    Permission::create(['app_key' => 'warehouse', 'key' => 'stock.read', 'full_key' => 'warehouse:stock.read']);
    Role::create(['app_key' => 'warehouse', 'key' => 'op', 'full_key' => 'warehouse:op', 'label' => 'Operator']);

    $res = $this->getJson('/api/iam/v1/policies-wizard/permissions?app=warehouse', ['X-Test-Auth' => 'adm']);

    $res->assertOk();
    expect(collect($res->json('data.permissions'))->pluck('full_key')->all())->toContain('warehouse:stock.read')
        ->and(collect($res->json('data.roles'))->pluck('full_key')->all())->toContain('warehouse:op');
});

it('preview NON scrive nulla e usa list-subjects (M16) per l\'impatto', function () {
    wizGrant('adm', ['iam:policies.read']);
    // usr_x è editor di doc:5 → deve comparire fra i current_holders impattati.
    app(RelationWriter::class)->grant(new SubjectRef('user', 'usr_x'), 'editor', new ResourceRef('doc', '5'));

    $res = $this->postJson('/api/iam/v1/policies-wizard/preview', [
        'subject' => ['type' => 'user', 'id' => 'usr_1'],
        'privilege_type' => 'permission', 'privilege_key' => 'warehouse:stock.adjust',
        'application' => 'warehouse',
        'relation' => 'editor', 'object' => ['type' => 'doc', 'id' => '5'],
    ], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'p1']);

    $res->assertOk()
        ->assertJsonPath('data.writes', false)
        ->assertJsonPath('data.current_decision.allowed', false);
    expect(collect($res->json('data.impact.current_holders'))->pluck('id')->all())->toContain('usr_x');

    // Invariante: nessun grant materializzato dalla preview.
    expect(Grant::query()->where('subject_id', 'usr_1')->where('privilege_key', 'warehouse:stock.adjust')->exists())->toBeFalse();
});

it('commit crea il grant ed è idempotente', function () {
    wizGrant('adm', ['iam:grants.manage']);
    $body = [
        'subject' => ['type' => 'user', 'id' => 'usr_1'],
        'privilege_type' => 'permission', 'privilege_key' => 'warehouse:stock.adjust', 'application' => 'warehouse',
    ];

    $first = $this->postJson('/api/iam/v1/policies-wizard/commit', $body, ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'c1']);
    $first->assertStatus(201)->assertJsonPath('data.created', true);

    // Secondo commit identico (Idempotency-Key diversa) → idempotente di dominio: nessun duplicato.
    $second = $this->postJson('/api/iam/v1/policies-wizard/commit', $body, ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'c2']);
    $second->assertOk()->assertJsonPath('data.created', false);

    expect(Grant::query()->where('subject_id', 'usr_1')->where('privilege_key', 'warehouse:stock.adjust')->count())->toBe(1);
});
