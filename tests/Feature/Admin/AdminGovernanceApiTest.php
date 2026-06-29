<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Padosoft\Iam\Domain\Authorization\Models\Grant;
use Padosoft\Iam\Domain\Governance\Requests\Models\AccessRequest;
use Padosoft\Iam\Domain\Governance\Reviews\Models\ReviewItem;

uses(RefreshDatabase::class);

// bindTestResolver()/grantAdmin() sono globali (AdminUsersApiTest.php).
beforeEach(fn () => bindTestResolver());

function subjectGrant(string $subjectId = 'usr_g'): Grant
{
    return Grant::create([
        'subject_type' => 'user', 'subject_id' => $subjectId,
        'privilege_type' => 'permission', 'privilege_key' => 'warehouse:stock.read', 'application_key' => 'warehouse',
    ]);
}

it('access-reviews: crea, apre e certifica una campagna', function () {
    grantAdmin('adm', ['iam:access_review.manage']);
    $grant = subjectGrant();
    $h = ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'c1'];

    $create = $this->postJson('/api/iam/v1/access-reviews/campaigns', ['name' => 'Q1', 'on_unconfirmed' => 'revoke', 'scope_json' => ['application_keys' => ['warehouse']]], $h);
    $create->assertStatus(201);
    $campaignId = $create->json('data.id');

    $this->postJson("/api/iam/v1/access-reviews/campaigns/{$campaignId}/open", [], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'c2'])
        ->assertOk()->assertJsonPath('data.items_created', 1);

    $item = ReviewItem::query()->where('campaign_id', $campaignId)->firstOrFail();
    $this->postJson("/api/iam/v1/access-reviews/items/{$item->id}/certify", [], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'c3'])
        ->assertOk()->assertJsonPath('data.decision', 'approved');

    expect($grant->fresh()->revoked_at)->toBeNull();
});

it('access-reviews: revoca di un item rimuove il grant', function () {
    grantAdmin('adm', ['iam:access_review.manage']);
    $grant = subjectGrant();
    $h = ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'r1'];
    $campaignId = $this->postJson('/api/iam/v1/access-reviews/campaigns', ['name' => 'Q1', 'scope_json' => ['application_keys' => ['warehouse']]], $h)->json('data.id');
    $this->postJson("/api/iam/v1/access-reviews/campaigns/{$campaignId}/open", [], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'r2']);
    $item = ReviewItem::query()->where('campaign_id', $campaignId)->firstOrFail();

    $this->postJson("/api/iam/v1/access-reviews/items/{$item->id}/revoke", ['note' => 'stale'], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'r3'])
        ->assertOk()->assertJsonPath('data.decision', 'revoked');

    expect($grant->fresh()->revoked_at)->not->toBeNull();
});

it('access-reviews senza permesso è 403', function () {
    $this->getJson('/api/iam/v1/access-reviews/campaigns', ['X-Test-Auth' => 'adm'])->assertStatus(403);
});

it('recommendations/least-privilege ritorna le proposte draft', function () {
    grantAdmin('adm', ['iam:least_privilege.view']);
    subjectGrant(); // grant permission diretto → direct_permission

    $res = $this->getJson('/api/iam/v1/recommendations/least-privilege', ['X-Test-Auth' => 'adm']);

    $res->assertOk();
    expect($res->json('data.count'))->toBeGreaterThan(0)
        ->and(collect($res->json('data.recommendations'))->pluck('type'))->toContain('direct_permission');
});

it('access-requests: approva una richiesta pending creando un grant time-boxed', function () {
    grantAdmin('adm', ['iam:access_request.review']);
    $req = AccessRequest::create([
        'requester_type' => 'user', 'requester_id' => 'usr_req',
        'application_key' => 'warehouse', 'role_key' => 'warehouse:op',
        'request_policy_json' => ['max_duration' => 'P7D'],
    ]);

    $res = $this->postJson("/api/iam/v1/access-requests/{$req->id}/approve", [], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'a1']);

    $res->assertOk()->assertJsonPath('data.status', 'approved');
    expect(Grant::query()->where('source', 'access_request')->where('subject_id', 'usr_req')->exists())->toBeTrue();
});

it('access-requests: approve con max_duration malformata è 422 (non 409)', function () {
    grantAdmin('adm', ['iam:access_request.review']);
    $req = AccessRequest::create([
        'requester_type' => 'user', 'requester_id' => 'usr_req',
        'application_key' => 'warehouse', 'role_key' => 'warehouse:op',
        'request_policy_json' => ['max_duration' => 'P30'], // typo ISO-8601
    ]);

    $this->postJson("/api/iam/v1/access-requests/{$req->id}/approve", [], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'bad1'])
        ->assertStatus(422);
});

it('access-reviews: ri-aprire una campagna completata è 409 (non 500)', function () {
    grantAdmin('adm', ['iam:access_review.manage']);
    $h = ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'k1'];
    // Scope su un'app senza grant → 0 item, così il grant-permesso dell'admin non viene certificato/revocato.
    $campaignId = $this->postJson('/api/iam/v1/access-reviews/campaigns', ['name' => 'Q1', 'scope_json' => ['application_keys' => ['warehouse']]], $h)->json('data.id');
    $this->postJson("/api/iam/v1/access-reviews/campaigns/{$campaignId}/open", [], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'k2']);
    $this->postJson("/api/iam/v1/access-reviews/campaigns/{$campaignId}/close", [], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'k3']);

    $this->postJson("/api/iam/v1/access-reviews/campaigns/{$campaignId}/open", [], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'k4'])
        ->assertStatus(409);
});

it('access-requests: reject senza creare grant', function () {
    grantAdmin('adm', ['iam:access_request.review']);
    $req = AccessRequest::create([
        'requester_type' => 'user', 'requester_id' => 'usr_req',
        'application_key' => 'warehouse', 'role_key' => 'warehouse:op',
    ]);

    $this->postJson("/api/iam/v1/access-requests/{$req->id}/reject", ['note' => 'no'], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'a2'])
        ->assertOk()->assertJsonPath('data.status', 'rejected');

    expect(Grant::query()->where('source', 'access_request')->exists())->toBeFalse();
});
