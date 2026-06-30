<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Iam\Domain\Authorization\Models\Grant;
use Padosoft\Iam\Domain\Governance\Requests\Models\AccessRequest;
use Padosoft\Iam\Domain\Governance\Requests\Models\ApprovalStep;
use Padosoft\Iam\Http\Admin\Support\AdminActorResolver;
use Padosoft\Iam\Http\Admin\Support\AdminContext;

uses(RefreshDatabase::class);

// Self-contained: resolver di test via X-Test-Auth (super admin, org null).
function chainBind(): void
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
function chainGrant(string $subjectId, array $permissions): void
{
    foreach ($permissions as $perm) {
        Grant::create([
            'subject_type' => 'user', 'subject_id' => $subjectId,
            'privilege_type' => 'permission', 'privilege_key' => $perm,
        ]);
    }
}

/** Crea una richiesta pending con N step pending (posizioni 1..N). */
function chainRequest(string $requester = 'usr_req', int $steps = 2): AccessRequest
{
    $req = AccessRequest::create([
        'requester_type' => 'user', 'requester_id' => $requester,
        'application_key' => 'warehouse', 'role_key' => 'warehouse:op',
        'request_policy_json' => ['max_duration' => 'P7D'],
    ]);
    for ($i = 1; $i <= $steps; $i++) {
        ApprovalStep::create([
            'access_request_id' => $req->id, 'position' => $i,
            'approver_type' => 'user', 'approver_ref' => "mgr{$i}",
        ]);
    }

    return $req;
}

function chainStep(AccessRequest $req, int $position): ApprovalStep
{
    return ApprovalStep::query()->where('access_request_id', $req->id)->where('position', $position)->firstOrFail();
}

beforeEach(fn () => chainBind());

it('rifiuta 403 fail-closed senza permesso', function () {
    $req = chainRequest();
    $this->postJson("/api/iam/v1/access-requests/{$req->id}/steps/{$req->id}/approve", [], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'k'])
        ->assertStatus(403);
});

it('AND sequenziale: il grant nasce SOLO all\'ultimo step', function () {
    chainGrant('adm', ['iam:access_request.review']);
    $req = chainRequest('usr_req', 2);
    $s1 = chainStep($req, 1);
    $s2 = chainStep($req, 2);

    // Non si può approvare lo step 2 prima dello step 1 (ordine) → 409.
    $this->postJson("/api/iam/v1/access-requests/{$req->id}/steps/{$s2->id}/approve", [], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'a0'])
        ->assertStatus(409);

    // Step 1 approvato → la catena prosegue, NESSUN grant ancora, richiesta ancora pending.
    $this->postJson("/api/iam/v1/access-requests/{$req->id}/steps/{$s1->id}/approve", [], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'a1'])
        ->assertOk()->assertJsonPath('data.granted', false)->assertJsonPath('data.request.status', 'pending');
    expect(Grant::query()->where('source', 'access_request')->where('subject_id', 'usr_req')->exists())->toBeFalse();

    // Step 2 (finale) → grant emesso, richiesta approved.
    $this->postJson("/api/iam/v1/access-requests/{$req->id}/steps/{$s2->id}/approve", [], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'a2'])
        ->assertOk()->assertJsonPath('data.granted', true)->assertJsonPath('data.request.status', 'approved');
    expect(Grant::query()->where('source', 'access_request')->where('subject_id', 'usr_req')->exists())->toBeTrue();
});

it('un reject su qualunque step → richiesta rejected (fail-closed, nessun grant)', function () {
    chainGrant('adm', ['iam:access_request.review']);
    $req = chainRequest('usr_req', 2);
    $s1 = chainStep($req, 1);
    $s2 = chainStep($req, 2);

    $this->postJson("/api/iam/v1/access-requests/{$req->id}/steps/{$s1->id}/reject", ['note' => 'no'], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'r1'])
        ->assertOk()->assertJsonPath('data.request.status', 'rejected');
    expect(Grant::query()->where('source', 'access_request')->exists())->toBeFalse();

    // La richiesta non è più pending: approvare lo step 2 ora è 409.
    $this->postJson("/api/iam/v1/access-requests/{$req->id}/steps/{$s2->id}/approve", [], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'r2'])
        ->assertStatus(409);
});

it('una catena a 1 step coincide col comportamento M8 (grant immediato all\'approvazione)', function () {
    chainGrant('adm', ['iam:access_request.review']);
    $req = chainRequest('usr_req', 1);
    $s1 = chainStep($req, 1);

    $this->postJson("/api/iam/v1/access-requests/{$req->id}/steps/{$s1->id}/approve", [], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'a1'])
        ->assertOk()->assertJsonPath('data.granted', true)->assertJsonPath('data.request.status', 'approved');
    expect(Grant::query()->where('source', 'access_request')->where('subject_id', 'usr_req')->exists())->toBeTrue();
});

it('l\'approvazione singola legacy è bloccata (409) se la richiesta ha una catena multi-step', function () {
    chainGrant('adm', ['iam:access_request.review']);
    $req = chainRequest('usr_req', 2);

    // Bypassare la catena con l'endpoint M8 violerebbe "grant solo a fine catena" → fail-closed 409.
    $this->postJson("/api/iam/v1/access-requests/{$req->id}/approve", [], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'la'])
        ->assertStatus(409);
    expect(Grant::query()->where('source', 'access_request')->exists())->toBeFalse();
});

it('self-approval di uno step non è consentita (409)', function () {
    chainGrant('adm', ['iam:access_request.review']);
    $req = chainRequest('adm', 1); // il richiedente È l'attore
    $s1 = chainStep($req, 1);

    $this->postJson("/api/iam/v1/access-requests/{$req->id}/steps/{$s1->id}/approve", [], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'sa'])
        ->assertStatus(409);
});

it('elenca gli step della catena', function () {
    chainGrant('adm', ['iam:access_request.review']);
    $req = chainRequest('usr_req', 2);

    $res = $this->getJson("/api/iam/v1/access-requests/{$req->id}/steps", ['X-Test-Auth' => 'adm']);

    $res->assertOk();
    expect($res->json('data.steps'))->toHaveCount(2)
        ->and(collect($res->json('data.steps'))->pluck('position')->all())->toBe([1, 2]);
});
