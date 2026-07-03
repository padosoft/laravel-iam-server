<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Padosoft\Iam\Domain\OAuth\Models\OauthClient;
use Padosoft\Iam\Domain\OAuth\Repositories\ClientRepository;

uses(RefreshDatabase::class);

// bindTestResolver()/grantAdmin() (AdminUsersApiTest.php) + validManifest()/submitApproveApply() (Applications helpers).
beforeEach(fn () => bindTestResolver());

it('client: rotazione mantiene valido il vecchio secret nel grace, poi scade (rollover zero-downtime)', function () {
    // Un client con secret noto (per poter verificare il vecchio nel grace con UNA sola rotazione).
    OauthClient::register(['client_id' => 'cli_x', 'name' => 'X', 'is_confidential' => true, 'grants' => ['client_credentials']], 'ORIGINAL-SECRET');
    $repo = new ClientRepository;

    $client = OauthClient::query()->where('client_id', 'cli_x')->firstOrFail();
    $new = $client->rotateSecret(259200, null); // grace 72h, nessuna scadenza

    // Entrambi validi nella finestra di grace → l'app aggiorna senza downtime.
    expect($repo->validateClient('cli_x', $new, null))->toBeTrue()
        ->and($repo->validateClient('cli_x', 'ORIGINAL-SECRET', null))->toBeTrue();

    // Oltre il grace (72h) il vecchio smette; il nuovo resta.
    $this->travel(73)->hours();
    expect($repo->validateClient('cli_x', 'ORIGINAL-SECRET', null))->toBeFalse()
        ->and($repo->validateClient('cli_x', $new, null))->toBeTrue();
});

it('client: una seconda rotazione mentre il grace è attivo è 409 (non orfaneggia il secret originale)', function () {
    submitApproveApply(validManifest());
    grantAdmin('adm', ['iam:clients.manage']);

    $this->postJson('/api/iam/v1/applications/warehouse/rotate-secret', [], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'r1'])->assertOk();
    // Il grace del primo secret è ancora attivo → seconda rotazione bloccata.
    $this->postJson('/api/iam/v1/applications/warehouse/rotate-secret', [], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'r2'])->assertStatus(409);

    // Dopo il grace si può ruotare di nuovo.
    $this->travel(73)->hours();
    $this->postJson('/api/iam/v1/applications/warehouse/rotate-secret', [], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'r3'])->assertOk();
});

it('client: GET /client espone lo stato del secret; revoke lo uccide', function () {
    submitApproveApply(validManifest());
    grantAdmin('adm', ['iam:applications.read', 'iam:clients.manage']);

    $info = $this->getJson('/api/iam/v1/applications/warehouse/client', ['X-Test-Auth' => 'adm'])->assertOk();
    expect($info->json('data.client_id'))->toBe('cli_warehouse')
        ->and($info->json('data.secret_status'))->toBe('ok'); // nessun ttl → non scade

    $this->postJson('/api/iam/v1/applications/warehouse/revoke-client', [], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'rv1'])
        ->assertOk()->assertJsonPath('data.revoked', true);

    // Un client revocato non autentica più e il suo stato è "revoked".
    expect((new ClientRepository)->validateClient('cli_warehouse', 'anything', null))->toBeFalse();
    $this->getJson('/api/iam/v1/applications/warehouse/client', ['X-Test-Auth' => 'adm'])
        ->assertOk()->assertJsonPath('data.secret_status', 'revoked');

    // Ruotare un client revocato è 409 (non emette un secret che poi non autenticherebbe mai).
    $this->postJson('/api/iam/v1/applications/warehouse/rotate-secret', [], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'rv2'])
        ->assertStatus(409);
});

it('client: lo stato è "expiring"/"expired" secondo secret_expires_at', function () {
    config(['iam.oauth.client_secret_ttl' => 3600, 'iam.oauth.client_secret_warn_days' => 14]); // scade in 1h
    submitApproveApply(validManifest());
    grantAdmin('adm', ['iam:applications.read']);

    // Con ttl 1h la scadenza è entro la soglia di 14 giorni → "expiring".
    $this->getJson('/api/iam/v1/applications/warehouse/client', ['X-Test-Auth' => 'adm'])
        ->assertOk()->assertJsonPath('data.secret_status', 'expiring');

    // Oltre la scadenza → "expired" (soft: l'auth col secret resta valida, è solo un alert).
    $this->travel(2)->hours();
    $this->getJson('/api/iam/v1/applications/warehouse/client', ['X-Test-Auth' => 'adm'])
        ->assertOk()->assertJsonPath('data.secret_status', 'expired');
});

it('client: rotate/revoke senza iam:clients.manage è 403', function () {
    submitApproveApply(validManifest());
    grantAdmin('adm', ['iam:applications.read']); // niente clients.manage

    $this->postJson('/api/iam/v1/applications/warehouse/rotate-secret', [], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'r9'])
        ->assertStatus(403);
    $this->postJson('/api/iam/v1/applications/warehouse/revoke-client', [], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'rv9'])
        ->assertStatus(403);
});
