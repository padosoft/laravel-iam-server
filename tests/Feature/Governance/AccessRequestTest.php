<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Iam\Domain\Audit\Models\AuditEvent;
use Padosoft\Iam\Domain\Authorization\Models\Grant;
use Padosoft\Iam\Domain\Authorization\Models\Role;
use Padosoft\Iam\Domain\Governance\Requests\AccessRequestService;
use Padosoft\Iam\Domain\Governance\Requests\RequestCatalog;
use Padosoft\Iam\Domain\Identity\Models\User;
use Padosoft\Iam\Domain\Organizations\Models\Membership;
use Padosoft\Iam\Domain\Organizations\Models\Organization;

uses(RefreshDatabase::class);

/**
 * Scenario base: feature access_request accesa per l'app warehouse, ruolo self_requestable con
 * visibility members_of_org, richiedente con il permesso d'uso e membro attivo dell'org.
 *
 * @return array{role: Role, requester: SubjectRef, org: Organization, user: User}
 */
function arScenario(array $roleOverrides = []): array
{
    config(['iam-governance.features.access_request.apps.warehouse.enabled' => 'on']);

    $org = Organization::create(['key' => 'acme', 'name' => 'Acme']);
    $user = User::create(['email' => 'op@acme.it']);
    Membership::create(['organization_id' => $org->id, 'user_id' => $user->id, 'status' => 'active']);

    // Gate 2: permesso d'uso del catalogo (grant globale).
    Grant::create([
        'subject_type' => 'user', 'subject_id' => $user->id,
        'privilege_type' => 'permission', 'privilege_key' => 'iam:access_request.use',
    ]);

    $role = Role::create(array_merge([
        'app_key' => 'warehouse', 'key' => 'stock_operator', 'full_key' => 'warehouse:stock_operator',
        'label' => 'Stock Operator', 'self_requestable' => true,
        'request_json' => [
            'visibility' => ['policy' => 'members_of_org'],
            'approvers' => ['app_owner', 'warehouse:manager'],
            'max_duration' => 'P30D',
            'requires_justification' => true,
        ],
    ], $roleOverrides));

    return ['role' => $role, 'requester' => new SubjectRef('user', $user->id), 'org' => $org, 'user' => $user];
}

it('il catalogo mostra il ruolo quando tutti e tre i cancelli sono soddisfatti', function () {
    ['requester' => $req, 'org' => $org, 'role' => $role] = arScenario();

    $visible = app(RequestCatalog::class)->visibleRoles($req, $org->id, 'warehouse');

    expect($visible)->toHaveCount(1)
        ->and($visible[0]->full_key)->toBe($role->full_key);
});

it('il catalogo è vuoto senza il permesso d\'uso (gate 2 default-deny)', function () {
    ['requester' => $req, 'org' => $org] = arScenario();
    Grant::query()->where('privilege_key', 'iam:access_request.use')->delete();

    expect(app(RequestCatalog::class)->visibleRoles($req, $org->id, 'warehouse'))->toBe([]);
});

it('il catalogo nasconde il ruolo se la FeatureScope è spenta per l\'app (gate 1)', function () {
    ['requester' => $req, 'org' => $org] = arScenario();
    config(['iam-governance.features.access_request.apps.warehouse.enabled' => 'off']);

    expect(app(RequestCatalog::class)->visibleRoles($req, $org->id, 'warehouse'))->toBe([]);
});

it('il catalogo nasconde un ruolo non self_requestable (gate 3a)', function () {
    ['requester' => $req, 'org' => $org] = arScenario(['self_requestable' => false]);

    expect(app(RequestCatalog::class)->visibleRoles($req, $org->id, 'warehouse'))->toBe([]);
});

it('il catalogo nasconde il ruolo se la visibility policy non è soddisfatta (gate 3b)', function () {
    ['requester' => $req, 'org' => $org, 'user' => $user] = arScenario();
    // Non più membro attivo → members_of_org fallisce.
    Membership::query()->where('user_id', $user->id)->update(['status' => 'removed']);

    expect(app(RequestCatalog::class)->visibleRoles($req, $org->id, 'warehouse'))->toBe([]);
});

it('una visibility policy sconosciuta è fail-closed (non visibile)', function () {
    ['requester' => $req, 'org' => $org] = arScenario([
        'request_json' => ['visibility' => ['policy' => 'mystery'], 'max_duration' => 'P7D'],
    ]);

    expect(app(RequestCatalog::class)->visibleRoles($req, $org->id, 'warehouse'))->toBe([]);
});

it('submit crea una richiesta pending con la catena di approver', function () {
    ['requester' => $req, 'org' => $org] = arScenario();

    $request = app(AccessRequestService::class)->submit($req, 'warehouse:stock_operator', 'mi serve per il turno', $org->id);

    expect($request->status)->toBe('pending')
        ->and($request->approver_chain_json)->toBe(['app_owner', 'warehouse:manager'])
        ->and(AuditEvent::query()->where('event_type', 'iam.access_request.submitted')->exists())->toBeTrue();
});

it('submit richiede la giustificazione quando il manifest la impone', function () {
    ['requester' => $req, 'org' => $org] = arScenario();

    expect(fn () => app(AccessRequestService::class)->submit($req, 'warehouse:stock_operator', null, $org->id))
        ->toThrow(InvalidArgumentException::class);
});

it('submit è rifiutato per un ruolo non richiedibile (non rivela il catalogo)', function () {
    ['requester' => $req, 'org' => $org] = arScenario(['self_requestable' => false]);

    expect(fn () => app(AccessRequestService::class)->submit($req, 'warehouse:stock_operator', 'x', $org->id))
        ->toThrow(RuntimeException::class);
});

it('approve crea un grant time-boxed collegato e audita', function () {
    ['requester' => $req, 'org' => $org] = arScenario();
    $service = app(AccessRequestService::class);
    $request = $service->submit($req, 'warehouse:stock_operator', 'turno notte', $org->id);

    $grant = $service->approve($request, 'user:owner');

    expect($request->fresh()->status)->toBe('approved')
        ->and($request->fresh()->granted_grant_id)->toBe($grant->id)
        ->and($grant->source)->toBe('access_request')
        ->and($grant->privilege_type)->toBe('role')
        ->and($grant->privilege_key)->toBe('warehouse:stock_operator')
        ->and($grant->approval_ref)->toBe($request->id)
        ->and($grant->valid_until)->not->toBeNull()
        ->and($grant->valid_until->greaterThan(now()->addDays(29)))->toBeTrue()
        ->and(AuditEvent::query()->where('event_type', 'iam.access_request.approved')->exists())->toBeTrue();
});

it('approve due volte è rifiutato (idempotenza sullo stato)', function () {
    ['requester' => $req, 'org' => $org] = arScenario();
    $service = app(AccessRequestService::class);
    $request = $service->submit($req, 'warehouse:stock_operator', 'x', $org->id);
    $service->approve($request, 'user:owner');

    expect(fn () => $service->approve($request->fresh(), 'user:owner'))->toThrow(RuntimeException::class);
});

it('reject imposta lo stato rejected senza creare grant', function () {
    ['requester' => $req, 'org' => $org] = arScenario();
    $service = app(AccessRequestService::class);
    $request = $service->submit($req, 'warehouse:stock_operator', 'x', $org->id);

    $service->reject($request, 'user:owner', 'non autorizzato');

    expect($request->fresh()->status)->toBe('rejected')
        ->and(Grant::query()->where('source', 'access_request')->exists())->toBeFalse();
});

it('cancel è consentito solo al richiedente', function () {
    ['requester' => $req, 'org' => $org] = arScenario();
    $service = app(AccessRequestService::class);
    $request = $service->submit($req, 'warehouse:stock_operator', 'x', $org->id);

    $other = new SubjectRef('user', 'usr_intruder');
    expect(fn () => $service->cancel($request, $other))->toThrow(RuntimeException::class);

    $service->cancel($request, $req);
    expect($request->fresh()->status)->toBe('cancelled');
});

it('un richiedente non può auto-approvare la propria richiesta (SoD)', function () {
    ['requester' => $req, 'org' => $org] = arScenario();
    $service = app(AccessRequestService::class);
    $request = $service->submit($req, 'warehouse:stock_operator', 'x', $org->id);

    expect(fn () => $service->approve($request, (string) $req))->toThrow(RuntimeException::class);
});

it('submit blocca richieste pending duplicate per lo stesso ruolo', function () {
    ['requester' => $req, 'org' => $org] = arScenario();
    $service = app(AccessRequestService::class);
    $service->submit($req, 'warehouse:stock_operator', 'x', $org->id);

    expect(fn () => $service->submit($req, 'warehouse:stock_operator', 'x', $org->id))
        ->toThrow(RuntimeException::class);
});

it('approve con max_duration malformata fallisce (no grant permanente da typo)', function () {
    ['requester' => $req, 'org' => $org] = arScenario([
        'request_json' => ['visibility' => ['policy' => 'members_of_org'], 'max_duration' => 'P30'],
    ]);
    $service = app(AccessRequestService::class);
    $request = $service->submit($req, 'warehouse:stock_operator', null, $org->id);

    expect(fn () => $service->approve($request, 'user:owner'))->toThrow(InvalidArgumentException::class)
        ->and(Grant::query()->where('source', 'access_request')->exists())->toBeFalse();
});

it('approve rifiuta se il soggetto possiede già un accesso attivo per il ruolo', function () {
    ['requester' => $req, 'org' => $org, 'user' => $user] = arScenario();
    // Grant equivalente già attivo.
    Grant::create([
        'organization_id' => $org->id, 'application_key' => 'warehouse',
        'subject_type' => 'user', 'subject_id' => $user->id,
        'privilege_type' => 'role', 'privilege_key' => 'warehouse:stock_operator',
    ]);
    $service = app(AccessRequestService::class);
    $request = $service->submit($req, 'warehouse:stock_operator', 'x', $org->id);

    expect(fn () => $service->approve($request, 'user:owner'))->toThrow(RuntimeException::class);
});

it('members_of_org con org null è fail-closed (catalogo globale non rivela ruoli per-org)', function () {
    ['requester' => $req] = arScenario();
    config(['iam-governance.features.access_request.default' => 'on']);

    // Nessuna org nel contesto → members_of_org non verificabile → ruolo non visibile.
    expect(app(RequestCatalog::class)->visibleRoles($req, null, 'warehouse'))->toBe([]);
});

it('cancel registra decided_by del richiedente', function () {
    ['requester' => $req, 'org' => $org] = arScenario();
    $service = app(AccessRequestService::class);
    $request = $service->submit($req, 'warehouse:stock_operator', 'x', $org->id);

    $service->cancel($request, $req);

    expect($request->fresh()->decided_by)->toBe((string) $req);
});

it('status/granted_grant_id NON sono mass-assignable (no auto-approvazione)', function () {
    ['requester' => $req, 'org' => $org] = arScenario();
    $request = app(AccessRequestService::class)->submit($req, 'warehouse:stock_operator', 'x', $org->id);

    $request->fill(['status' => 'approved', 'granted_grant_id' => 'grn_fake'])->save();

    expect($request->fresh()->status)->toBe('pending')
        ->and($request->fresh()->granted_grant_id)->toBeNull();
});
