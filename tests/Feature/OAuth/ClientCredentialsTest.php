<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Padosoft\Iam\Contracts\Crypto\TokenSigner;
use Padosoft\Iam\Domain\OAuth\Models\OauthAccessToken;
use Padosoft\Iam\Domain\OAuth\Models\OauthClient;
use Padosoft\Iam\Domain\OAuth\Models\OauthScope;
use Padosoft\Iam\Domain\Organizations\Models\Organization;

uses(RefreshDatabase::class);

/**
 * @param  list<string>  $grants
 */
function makeClient(array $grants = ['client_credentials'], string $secret = 's3cret-value', bool $confidential = true): OauthClient
{
    $org = Organization::query()->create(['key' => 'acme', 'name' => 'Acme']);
    OauthScope::query()->create(['identifier' => 'stock.read']);

    return OauthClient::register([
        'client_id' => 'cli_test',
        'name' => 'Test Client',
        'grants' => $grants,
        'scopes' => ['stock.read'],
        'is_confidential' => $confidential,
        'organization_id' => $org->id,
    ], $confidential ? $secret : null);
}

it('emette un access token via client_credentials con i claim IAM (policy_version, org, aud)', function () {
    makeClient();

    $response = $this->post('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => 'cli_test',
        'client_secret' => 's3cret-value',
        'scope' => 'stock.read',
    ]);

    $response->assertOk();
    expect($response->json('token_type'))->toBe('Bearer')
        ->and($response->json('access_token'))->toBeString();

    $jwt = $response->json('access_token');
    $claims = app(TokenSigner::class)->parse($jwt);

    expect($claims['client_id'])->toBe('cli_test')
        ->and($claims['sub'])->toBe('cli_test')
        ->and($claims['aud'])->toContain('cli_test')
        ->and($claims['scope'])->toBe('stock.read')
        ->and($claims['org'])->toBe('acme')
        ->and($claims['policy_version'])->toBe(1);
});

it('registra il token nel ledger (jti) per introspection/revoca', function () {
    makeClient();

    $jwt = $this->post('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => 'cli_test',
        'client_secret' => 's3cret-value',
        'scope' => 'stock.read',
    ])->json('access_token');

    $jti = app(TokenSigner::class)->parse($jwt)['jti'];

    expect(OauthAccessToken::query()->where('jti', $jti)->where('client_id', 'cli_test')->exists())->toBeTrue();
});

it('rifiuta il client con secret errato (invalid_client)', function () {
    makeClient();

    $this->post('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => 'cli_test',
        'client_secret' => 'wrong-secret',
    ])->assertStatus(401);
});

it('rifiuta un grant non dichiarato dal client (fail-closed)', function () {
    makeClient(grants: ['authorization_code']);

    $this->post('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => 'cli_test',
        'client_secret' => 's3cret-value',
    ])->assertStatus(401);
});

it('non concede scope oltre quelli dichiarati dal client (anti-escalation)', function () {
    makeClient();
    OauthScope::query()->create(['identifier' => 'admin.all']); // in catalogo ma NON ammesso al client

    $jwt = $this->post('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => 'cli_test',
        'client_secret' => 's3cret-value',
        'scope' => 'stock.read admin.all',
    ])->json('access_token');

    // admin.all viene filtrato: resta solo stock.read.
    expect(app(TokenSigner::class)->parse($jwt)['scope'])->toBe('stock.read');
});

it('rifiuta client_credentials a un client public (RFC 6749 §4.4)', function () {
    makeClient(grants: ['client_credentials'], confidential: false);

    $this->post('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => 'cli_test',
    ])->assertStatus(401);
});
