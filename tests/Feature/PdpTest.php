<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Iam\Domain\Authorization\Models\Grant;
use Padosoft\Iam\Domain\Authorization\Models\Permission;
use Padosoft\Iam\Domain\Authorization\Models\Role;
use Padosoft\Iam\Domain\Authorization\Pdp\DecisionQuery;
use Padosoft\Iam\Domain\Authorization\Pdp\NativeSqlEngine;
use Padosoft\Iam\Domain\Organizations\Models\Organization;

uses(RefreshDatabase::class);

function pdp(): NativeSqlEngine
{
    return new NativeSqlEngine;
}

/** @param array<string, mixed> $overrides */
function grantPerm(string $fullKey, array $overrides = []): Grant
{
    return Grant::create(array_merge([
        'subject_type' => 'user',
        'subject_id' => 'usr_1',
        'privilege_type' => 'permission',
        'privilege_key' => $fullKey,
        'application_key' => 'warehouse',
    ], $overrides));
}

function ask(string $permission, array $opts = []): DecisionQuery
{
    return new DecisionQuery(
        subject: new SubjectRef('user', $opts['subject'] ?? 'usr_1'),
        permission: $permission,
        organizationId: $opts['org'] ?? null,
        applicationKey: $opts['app'] ?? 'warehouse',
        resourceRef: $opts['resource'] ?? null,
        context: $opts['context'] ?? [],
        currentAal: $opts['aal'] ?? 'aal1',
    );
}

it('PERMIT: grant permission che combacia', function () {
    grantPerm('warehouse:stock.read');

    $d = pdp()->decide(ask('warehouse:stock.read'));

    expect($d->allowed)->toBeTrue()
        ->and($d->matched)->toBe([['type' => 'permission', 'key' => 'warehouse:stock.read']]);
});

it('DENY-OVERRIDES: un deny vince sempre sul permit', function () {
    grantPerm('warehouse:stock.read');
    grantPerm('warehouse:stock.read', ['effect' => 'deny']);

    $d = pdp()->decide(ask('warehouse:stock.read'));

    expect($d->allowed)->toBeFalse()
        ->and($d->matched[0]['type'])->toBe('deny');
});

it('DEFAULT-DENY: nessun grant → negato (fail-closed)', function () {
    $d = pdp()->decide(ask('warehouse:stock.read', ['subject' => 'nobody']));

    expect($d->allowed)->toBeFalse()
        ->and($d->matched)->toBe([]);
});

it('ABAC: la condizione filtra (amount <= 500)', function () {
    grantPerm('warehouse:stock.adjust', ['conditions_json' => ['amount' => ['<=' => 500]]]);

    expect(pdp()->decide(ask('warehouse:stock.adjust', ['context' => ['amount' => 300]]))->allowed)->toBeTrue()
        ->and(pdp()->decide(ask('warehouse:stock.adjust', ['context' => ['amount' => 900]]))->allowed)->toBeFalse();
});

it('RBAC: permit concesso tramite ruolo (espansione role→permissions)', function () {
    $perm = Permission::create(['app_key' => 'warehouse', 'key' => 'stock.adjust', 'full_key' => 'warehouse:stock.adjust']);
    $role = Role::create(['app_key' => 'warehouse', 'key' => 'stock_operator', 'full_key' => 'warehouse:stock_operator']);
    $role->permissions()->attach($perm->id);
    Grant::create([
        'subject_type' => 'user', 'subject_id' => 'usr_1',
        'privilege_type' => 'role', 'privilege_key' => 'warehouse:stock_operator',
        'application_key' => 'warehouse',
    ]);

    $d = pdp()->decide(ask('warehouse:stock.adjust'));

    expect($d->allowed)->toBeTrue()
        ->and($d->matched[0])->toBe(['type' => 'role', 'key' => 'warehouse:stock_operator']);
});

it('STEP-UP: permesso che lo richiede con AAL1 → allowed + requires_step_up=aal2', function () {
    Permission::create(['app_key' => 'warehouse', 'key' => 'stock.adjust', 'full_key' => 'warehouse:stock.adjust', 'requires_step_up' => true]);
    grantPerm('warehouse:stock.adjust');

    $low = pdp()->decide(ask('warehouse:stock.adjust', ['aal' => 'aal1']));
    expect($low->allowed)->toBeTrue()
        ->and($low->requiresStepUp)->toBeTrue()
        ->and($low->requiredAal)->toBe('aal2');

    $high = pdp()->decide(ask('warehouse:stock.adjust', ['aal' => 'aal2']));
    expect($high->requiresStepUp)->toBeFalse();
});

it('SCOPE: grant limitato a una risorsa concede solo su quella', function () {
    grantPerm('warehouse:stock.adjust', ['resource_ref' => 'wh_milan']);

    expect(pdp()->decide(ask('warehouse:stock.adjust', ['resource' => 'wh_milan']))->allowed)->toBeTrue()
        ->and(pdp()->decide(ask('warehouse:stock.adjust', ['resource' => 'wh_rome']))->allowed)->toBeFalse();
});

it('un grant revocato non concede (fail-closed, integrazione con M1)', function () {
    grantPerm('warehouse:stock.read')->revoke('admin');

    expect(pdp()->decide(ask('warehouse:stock.read'))->allowed)->toBeFalse();
});

it('EXPLAIN derivato + decision_id', function () {
    grantPerm('warehouse:stock.read');

    $d = pdp()->decide(ask('warehouse:stock.read'));

    expect($d->explanation)->not->toBeEmpty()
        ->and($d->decisionId)->toStartWith('dec_');
});

it('policy_version riflette l\'organizzazione (consistency token)', function () {
    $org = Organization::create(['key' => 'acme', 'name' => 'Acme']);
    $org->forceFill(['policy_version' => 42])->save();
    grantPerm('warehouse:stock.read', ['organization_id' => $org->id]);

    $d = pdp()->decide(ask('warehouse:stock.read', ['org' => $org->id]));

    expect($d->policyVersion)->toBe(42)
        ->and($d->allowed)->toBeTrue();
});

it('TENANT ISOLATION: grant di org_A non concede in query per org_B né senza org', function () {
    $a = Organization::create(['key' => 'a', 'name' => 'A']);
    $b = Organization::create(['key' => 'b', 'name' => 'B']);
    grantPerm('warehouse:stock.read', ['organization_id' => $a->id]);

    expect(pdp()->decide(ask('warehouse:stock.read', ['org' => $a->id]))->allowed)->toBeTrue()
        ->and(pdp()->decide(ask('warehouse:stock.read', ['org' => $b->id]))->allowed)->toBeFalse()
        ->and(pdp()->decide(ask('warehouse:stock.read', ['org' => null]))->allowed)->toBeFalse();
});

it('APP ISOLATION: grant app warehouse non concede in query per app billing', function () {
    grantPerm('warehouse:stock.read', ['application_key' => 'warehouse']);

    expect(pdp()->decide(ask('warehouse:stock.read', ['app' => 'warehouse']))->allowed)->toBeTrue()
        ->and(pdp()->decide(ask('warehouse:stock.read', ['app' => 'billing']))->allowed)->toBeFalse();
});

it('un permesso DEPRECATO non concede', function () {
    Permission::create(['app_key' => 'warehouse', 'key' => 'stock.adjust', 'full_key' => 'warehouse:stock.adjust', 'deprecated_at' => now()]);
    grantPerm('warehouse:stock.adjust');

    expect(pdp()->decide(ask('warehouse:stock.adjust'))->allowed)->toBeFalse();
});

it('un ruolo DEPRECATO non concede', function () {
    $perm = Permission::create(['app_key' => 'warehouse', 'key' => 'stock.adjust', 'full_key' => 'warehouse:stock.adjust']);
    $role = Role::create(['app_key' => 'warehouse', 'key' => 'r', 'full_key' => 'warehouse:r', 'deprecated_at' => now()]);
    $role->permissions()->attach($perm->id);
    Grant::create(['subject_type' => 'user', 'subject_id' => 'usr_1', 'privilege_type' => 'role', 'privilege_key' => 'warehouse:r', 'application_key' => 'warehouse']);

    expect(pdp()->decide(ask('warehouse:stock.adjust'))->allowed)->toBeFalse();
});

it('ABAC fail-closed: campo del context ASSENTE fa fallire la condizione', function () {
    grantPerm('warehouse:stock.adjust', ['conditions_json' => ['amount' => ['<=' => 500]]]);

    expect(pdp()->decide(ask('warehouse:stock.adjust', ['context' => []]))->allowed)->toBeFalse();
});

it('STEP-UP via ruolo: il requisito del permesso vale anche se concesso da ruolo', function () {
    $perm = Permission::create(['app_key' => 'warehouse', 'key' => 'stock.adjust', 'full_key' => 'warehouse:stock.adjust', 'requires_step_up' => true]);
    $role = Role::create(['app_key' => 'warehouse', 'key' => 'op', 'full_key' => 'warehouse:op']);
    $role->permissions()->attach($perm->id);
    Grant::create(['subject_type' => 'user', 'subject_id' => 'usr_1', 'privilege_type' => 'role', 'privilege_key' => 'warehouse:op', 'application_key' => 'warehouse']);

    $d = pdp()->decide(ask('warehouse:stock.adjust', ['aal' => 'aal1']));

    expect($d->allowed)->toBeTrue()->and($d->requiresStepUp)->toBeTrue();
});

it('check(): il contract array delega a decide()', function () {
    grantPerm('warehouse:stock.read');

    $r = pdp()->check([
        'subject' => ['type' => 'user', 'id' => 'usr_1'],
        'permission' => 'warehouse:stock.read',
        'application' => 'warehouse',
        'explain' => true,
    ]);

    expect($r['allowed'])->toBeTrue()
        ->and($r)->toHaveKey('decision_id');
});
