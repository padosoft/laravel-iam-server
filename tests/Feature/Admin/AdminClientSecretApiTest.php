<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Padosoft\Iam\Domain\OAuth\Repositories\ClientRepository;

uses(RefreshDatabase::class);

// bindTestResolver()/grantAdmin() (AdminUsersApiTest.php) + validManifest()/submitApproveApply() (Applications helpers).
beforeEach(fn () => bindTestResolver());

it('client: rotazione mantiene valido il vecchio secret nel grace, poi scade (rollover zero-downtime)', function () {
    submitApproveApply(validManifest()); // crea l'app "warehouse" + client cli_warehouse (confidential)
    grantAdmin('adm', ['iam:clients.manage']);
    $repo = new ClientRepository;

    // Prima rotazione → secret1 (corrente).
    $secret1 = $this->postJson('/api/iam/v1/applications/warehouse/rotate-secret', [], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'r1'])
        ->assertOk()->json('data.client_secret');
    expect($secret1)->toBeString()->and(strlen((string) $secret1))->toBe(48);
    expect($repo->validateClient('cli_warehouse', $secret1, null))->toBeTrue();

    // Seconda rotazione → secret2 corrente, secret1 diventa "previous" nel grace.
    $secret2 = $this->postJson('/api/iam/v1/applications/warehouse/rotate-secret', [], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'r2'])
        ->assertOk()->assertJsonPath('data.grace_active', true)->json('data.client_secret');

    // Entrambi validi nella finestra di grace → l'app aggiorna senza downtime.
    expect($repo->validateClient('cli_warehouse', $secret2, null))->toBeTrue()
        ->and($repo->validateClient('cli_warehouse', $secret1, null))->toBeTrue();

    // Oltre il grace (72h default) il vecchio smette; il nuovo resta.
    $this->travel(73)->hours();
    expect($repo->validateClient('cli_warehouse', $secret1, null))->toBeFalse()
        ->and($repo->validateClient('cli_warehouse', $secret2, null))->toBeTrue();
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
