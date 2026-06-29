<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Padosoft\Iam\Domain\Authorization\Models\Grant;
use Padosoft\Iam\Domain\Authorization\Models\Permission;
use Padosoft\Iam\Domain\Authorization\Models\Role;
use Padosoft\Iam\Domain\Governance\Recommendations\LeastPrivilegeRecommender;
use Padosoft\Iam\Domain\Organizations\Models\Organization;

uses(RefreshDatabase::class);

function lpGrant(array $overrides = []): Grant
{
    return Grant::create(array_merge([
        'subject_type' => 'user', 'subject_id' => 'usr_l',
        'privilege_type' => 'permission', 'privilege_key' => 'warehouse:stock.read',
        'application_key' => 'warehouse',
    ], $overrides));
}

/** @return list<string> i `type` delle raccomandazioni emesse */
function recTypes(?string $org = null): array
{
    return array_map(fn ($r) => $r->type, app(LeastPrivilegeRecommender::class)->analyze($org));
}

it('segnala un permesso diretto come candidato a ruolo', function () {
    lpGrant();

    expect(recTypes())->toContain('direct_permission');
});

it('segnala un grant non usato oltre la soglia (e mai un grant fresco)', function () {
    $stale = lpGrant(['subject_id' => 'usr_old']);
    $stale->forceFill(['last_used_at' => now()->subDays(120)])->save();
    lpGrant(['subject_id' => 'usr_new']); // appena creato e mai usato → non segnalato

    $recs = app(LeastPrivilegeRecommender::class)->analyze();
    $unused = array_values(array_filter($recs, fn ($r) => $r->type === 'unused_grant'));

    expect($unused)->toHaveCount(1)
        ->and($unused[0]->targetRef)->toBe($stale->id);
});

it('segnala un grant mai usato e creato da tempo come non usato', function () {
    $g = lpGrant(['subject_id' => 'usr_dormant']);
    $g->forceFill(['created_at' => now()->subDays(200)])->save();

    $recs = app(LeastPrivilegeRecommender::class)->analyze();
    $unused = array_values(array_filter($recs, fn ($r) => $r->type === 'unused_grant'));

    expect($unused)->toHaveCount(1)
        ->and($unused[0]->targetRef)->toBe($g->id);
});

it('segnala un grant privilegiato permanente come candidato a temporaneo (PIM)', function () {
    lpGrant(['subject_id' => 'usr_priv', 'is_privileged' => true]); // valid_until null

    expect(recTypes())->toContain('permanent_privileged');
});

it('segnala un ruolo troppo ampio oltre la soglia', function () {
    config(['iam-governance.least_privilege.wide_role_permissions' => 2]);
    $role = Role::create(['app_key' => 'warehouse', 'key' => 'super', 'full_key' => 'warehouse:super']);
    foreach (['a', 'b', 'c'] as $k) {
        $perm = Permission::create(['app_key' => 'warehouse', 'key' => $k, 'full_key' => "warehouse:{$k}"]);
        $role->permissions()->attach($perm->id);
    }

    $recs = app(LeastPrivilegeRecommender::class)->analyze();
    $wide = array_values(array_filter($recs, fn ($r) => $r->type === 'wide_role'));

    expect($wide)->toHaveCount(1)
        ->and($wide[0]->targetRef)->toBe('warehouse:super');
});

it('segnala una combinazione tossica quando il soggetto detiene tutte le chiavi', function () {
    config(['iam-governance.toxic_combinations' => [
        ['name' => 'pay_and_approve', 'all_of' => ['billing:pay.create', 'billing:pay.approve']],
    ]]);
    lpGrant(['subject_id' => 'usr_sod', 'privilege_key' => 'billing:pay.create', 'application_key' => 'billing']);
    lpGrant(['subject_id' => 'usr_sod', 'privilege_key' => 'billing:pay.approve', 'application_key' => 'billing']);

    $recs = app(LeastPrivilegeRecommender::class)->analyze();
    $toxic = array_values(array_filter($recs, fn ($r) => $r->type === 'toxic_combination'));

    expect($toxic)->toHaveCount(1)
        ->and($toxic[0]->subject)->toBe('user:usr_sod');
});

it('non segnala una combinazione tossica se manca anche solo una chiave', function () {
    config(['iam-governance.toxic_combinations' => [
        ['name' => 'pay_and_approve', 'all_of' => ['billing:pay.create', 'billing:pay.approve']],
    ]]);
    lpGrant(['subject_id' => 'usr_safe', 'privilege_key' => 'billing:pay.create', 'application_key' => 'billing']);

    expect(recTypes())->not->toContain('toxic_combination');
});

it('lo scan per-org segnala un ruolo ampio solo se concesso in quello scope', function () {
    config(['iam-governance.least_privilege.wide_role_permissions' => 2]);
    $org = Organization::create(['key' => 'acme', 'name' => 'Acme']);
    $role = Role::create(['app_key' => 'warehouse', 'key' => 'super', 'full_key' => 'warehouse:super']);
    foreach (['a', 'b', 'c'] as $k) {
        $perm = Permission::create(['app_key' => 'warehouse', 'key' => $k, 'full_key' => "warehouse:{$k}"]);
        $role->permissions()->attach($perm->id);
    }
    // Il ruolo è concesso nell'org acme.
    lpGrant(['subject_id' => 'usr_a', 'privilege_type' => 'role', 'privilege_key' => 'warehouse:super', 'organization_id' => $org->id]);

    $inScope = array_filter(app(LeastPrivilegeRecommender::class)->analyze($org->id), fn ($r) => $r->type === 'wide_role');
    $otherOrg = array_filter(app(LeastPrivilegeRecommender::class)->analyze('org_other'), fn ($r) => $r->type === 'wide_role');

    expect($inScope)->toHaveCount(1)
        ->and($otherOrg)->toBe([]);
});

it('le raccomandazioni sono solo draft: nessuna mutazione sui grant', function () {
    $g = lpGrant(['subject_id' => 'usr_priv', 'is_privileged' => true]);
    $g->forceFill(['last_used_at' => now()->subDays(200)])->save();

    app(LeastPrivilegeRecommender::class)->analyze();

    // Il grant resta intatto: il recommender propone, non agisce.
    expect($g->fresh()->revoked_at)->toBeNull()
        ->and($g->fresh()->valid_until)->toBeNull();
});

it('il comando iam:least-privilege:scan elenca le raccomandazioni', function () {
    lpGrant(['subject_id' => 'usr_priv', 'is_privileged' => true]);

    $this->artisan('iam:least-privilege:scan')
        ->assertSuccessful();
});
