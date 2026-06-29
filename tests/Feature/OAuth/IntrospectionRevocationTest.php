<?php

declare(strict_types=1);

use Illuminate\Auth\GenericUser;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Padosoft\Iam\Domain\OAuth\Models\OauthClient;
use Padosoft\Iam\Domain\OAuth\Models\OauthScope;
use Padosoft\Iam\Domain\Organizations\Models\Organization;
use Tests\TestCase;

uses(RefreshDatabase::class);

function svcClient(): void
{
    $org = Organization::query()->create(['key' => 'acme', 'name' => 'Acme']);
    OauthScope::query()->create(['identifier' => 'stock.read']);
    OauthClient::register([
        'client_id' => 'cli_svc',
        'name' => 'Service',
        'grants' => ['client_credentials'],
        'scopes' => ['stock.read'],
        'is_confidential' => true,
        'organization_id' => $org->id,
    ], 'svc-secret');
}

function svcToken(TestCase $test): string
{
    $token = $test->post('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => 'cli_svc',
        'client_secret' => 'svc-secret',
        'scope' => 'stock.read',
    ])->json('access_token');

    return is_string($token) ? $token : '';
}

it('introspect ritorna active=true e i claim per un access token valido', function () {
    svcClient();
    $token = svcToken($this);

    $res = $this->post('/oauth/introspect', [
        'token' => $token,
        'client_id' => 'cli_svc',
        'client_secret' => 'svc-secret',
    ]);

    $res->assertOk();
    expect($res->json('active'))->toBeTrue()
        ->and($res->json('client_id'))->toBe('cli_svc')
        ->and($res->json('scope'))->toBe('stock.read')
        ->and($res->json('exp'))->toBeInt()
        ->and($res->json('policy_version'))->toBe(1);
});

it('introspect richiede autenticazione client (401)', function () {
    svcClient();
    $token = svcToken($this);

    $this->post('/oauth/introspect', ['token' => $token])->assertStatus(401);
});

it('introspect non rivela il token di un ALTRO client (no cross-client disclosure)', function () {
    svcClient();
    $token = svcToken($this); // token di cli_svc

    // Un secondo client confidential, autenticato, NON deve poter introspettare token altrui.
    OauthClient::register([
        'client_id' => 'cli_other',
        'name' => 'Other',
        'grants' => ['client_credentials'],
        'is_confidential' => true,
    ], 'other-secret');

    $res = $this->post('/oauth/introspect', [
        'token' => $token,
        'client_id' => 'cli_other',
        'client_secret' => 'other-secret',
    ]);

    $res->assertOk();
    expect($res->json('active'))->toBeFalse();
});

it('introspect rifiuta un client public (senza secret) → 401', function () {
    $org = Organization::query()->create(['key' => 'acme', 'name' => 'Acme']);
    OauthClient::register([
        'client_id' => 'cli_pub',
        'name' => 'SPA',
        'grants' => ['authorization_code'],
        'is_confidential' => false,
        'organization_id' => $org->id,
    ], null);

    $this->post('/oauth/introspect', ['token' => 'whatever', 'client_id' => 'cli_pub'])->assertStatus(401);
});

it('revoke disattiva un access token (introspect successivo active=false)', function () {
    svcClient();
    $token = svcToken($this);

    $this->post('/oauth/revoke', [
        'token' => $token,
        'client_id' => 'cli_svc',
        'client_secret' => 'svc-secret',
    ])->assertStatus(200);

    $res = $this->post('/oauth/introspect', [
        'token' => $token,
        'client_id' => 'cli_svc',
        'client_secret' => 'svc-secret',
    ]);
    expect($res->json('active'))->toBeFalse();
});

it('revoke richiede autenticazione client (401)', function () {
    svcClient();
    $token = svcToken($this);

    $this->post('/oauth/revoke', ['token' => $token])->assertStatus(401);
});

it('revoke di un refresh token revoca l\'intera catena', function () {
    $org = Organization::query()->create(['key' => 'acme', 'name' => 'Acme']);
    OauthScope::query()->create(['identifier' => 'stock.read']);
    OauthClient::register([
        'client_id' => 'cli_conf',
        'name' => 'Confidential App',
        'grants' => ['authorization_code', 'refresh_token'],
        'scopes' => ['stock.read'],
        'redirect_uris' => [REDIRECT_URI],
        'is_confidential' => true,
        'is_first_party' => true,
        'organization_id' => $org->id,
    ], 'conf-secret');

    $pkce = pkcePair();
    $location = $this->actingAs(new GenericUser(['id' => 'usr_1']))
        ->get('/oauth/authorize?'.authorizeQuery($pkce['challenge'], ['client_id' => 'cli_conf']))
        ->headers->get('Location') ?? '';

    $refresh = $this->post('/oauth/token', [
        'grant_type' => 'authorization_code',
        'client_id' => 'cli_conf',
        'client_secret' => 'conf-secret',
        'redirect_uri' => REDIRECT_URI,
        'code' => codeFromRedirect($location),
        'code_verifier' => $pkce['verifier'],
    ])->json('refresh_token');

    $this->post('/oauth/revoke', [
        'token' => $refresh,
        'client_id' => 'cli_conf',
        'client_secret' => 'conf-secret',
    ])->assertStatus(200);

    // Il refresh token revocato non è più utilizzabile.
    $this->post('/oauth/token', [
        'grant_type' => 'refresh_token',
        'client_id' => 'cli_conf',
        'client_secret' => 'conf-secret',
        'refresh_token' => $refresh,
    ])->assertStatus(400);
});
