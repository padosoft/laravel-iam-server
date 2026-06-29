<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Padosoft\Iam\Domain\Audit\Models\AuditEvent;
use Padosoft\Iam\Domain\Authorization\Models\Grant;
use Padosoft\Iam\Domain\Identity\Models\Session;
use Padosoft\Iam\Domain\Identity\Models\User;

uses(RefreshDatabase::class);

// bindTestResolver() e grantAdmin() sono definite in AdminUsersApiTest.php (funzioni globali Pest).
beforeEach(fn () => bindTestResolver());

function makeSession(array $overrides = []): Session
{
    $userId = is_string($overrides['user_id'] ?? null) ? $overrides['user_id'] : 'usr_t';
    if (User::query()->whereKey($userId)->doesntExist()) {
        (new User)->forceFill(['id' => $userId, 'email' => $userId.'@x.it'])->save();
    }

    $s = new Session;
    $s->forceFill(array_merge([
        'user_id' => $userId, 'aal' => 'aal1', 'idle_timeout' => 900,
        'last_activity_at' => now(), 'absolute_expires_at' => now()->addHours(8),
    ], $overrides))->save();

    return $s;
}

it('decisions/check ritorna allow per un soggetto con grant valido', function () {
    grantAdmin('adm', ['iam:decisions.check']);
    Grant::create(['subject_type' => 'user', 'subject_id' => 'usr_t', 'privilege_type' => 'permission', 'privilege_key' => 'warehouse:stock.read', 'application_key' => 'warehouse']);

    $res = $this->postJson('/api/iam/v1/decisions/check', [
        'subject' => ['type' => 'user', 'id' => 'usr_t'],
        'application' => 'warehouse',
        'permission' => 'warehouse:stock.read',
    ], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'd1']);

    $res->assertOk()->assertJsonPath('data.allowed', true);
});

it('decisions/check è default-deny per un soggetto senza grant', function () {
    grantAdmin('adm', ['iam:decisions.check']);

    $res = $this->postJson('/api/iam/v1/decisions/check', [
        'subject' => ['type' => 'user', 'id' => 'nobody'],
        'permission' => 'warehouse:stock.read',
    ], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'd2']);

    $res->assertOk()->assertJsonPath('data.allowed', false);
});

it('decisions/check valida l\'input (422 senza subject.id)', function () {
    grantAdmin('adm', ['iam:decisions.check']);

    $this->postJson('/api/iam/v1/decisions/check', ['permission' => 'x'], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'd3'])
        ->assertStatus(422);
});

it('decisions/explain include la spiegazione', function () {
    grantAdmin('adm', ['iam:decisions.explain']);

    $res = $this->postJson('/api/iam/v1/decisions/explain', [
        'subject' => ['type' => 'user', 'id' => 'nobody'],
        'permission' => 'warehouse:stock.read',
    ], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'e1']);

    $res->assertOk();
    expect($res->json('data.explanation'))->toBeArray()->not->toBeEmpty();
});

it('decisions/check senza permesso è 403 fail-closed', function () {
    $this->postJson('/api/iam/v1/decisions/check', [
        'subject' => ['id' => 'x'], 'permission' => 'y',
    ], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'f1'])->assertStatus(403);
});

it('list-subjects/list-resources sono 501 (ReBAC v2)', function () {
    grantAdmin('adm', ['iam:decisions.explain']);

    $this->postJson('/api/iam/v1/decisions/list-subjects', [], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'l1'])
        ->assertStatus(501);
});

it('sessions: elenca e revoca una sessione (audit + idempotente)', function () {
    grantAdmin('adm', ['iam:sessions.read', 'iam:sessions.manage']);
    $s = makeSession();

    $this->getJson('/api/iam/v1/sessions', ['X-Test-Auth' => 'adm'])
        ->assertOk()->assertJsonPath('data.0.id', $s->id);

    $this->postJson("/api/iam/v1/sessions/{$s->id}/revoke", ['reason' => 'sospetto'], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 's1'])
        ->assertOk();

    expect($s->fresh()->revoked_at)->not->toBeNull()
        ->and(AuditEvent::query()->where('event_type', 'iam.session.revoked')->where('target_id', $s->id)->exists())->toBeTrue();
});

it('sessions/revoke-all revoca tutte le sessioni attive di un utente', function () {
    grantAdmin('adm', ['iam:sessions.manage']);
    makeSession(['user_id' => 'usr_z']);
    makeSession(['user_id' => 'usr_z']);

    $res = $this->postJson('/api/iam/v1/users/usr_z/sessions/revoke-all', [], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 's2']);

    $res->assertOk()->assertJsonPath('data.revoked', 2);
    expect(Session::query()->where('user_id', 'usr_z')->whereNull('revoked_at')->count())->toBe(0);
});
