<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Testing\TestResponse;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Ecdsa\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token\Builder;
use Padosoft\Iam\Domain\Applications\Manifest\ManifestRegistry;
use Padosoft\Iam\Domain\OAuth\Models\OauthClient;
use Padosoft\Iam\Domain\OAuth\Models\OauthScope;
use Padosoft\Iam\Domain\Organizations\Models\Organization;

uses(RefreshDatabase::class);

/**
 * private_key_jwt (RFC 7523): asymmetric client authentication with no shared secret. The client signs a
 * short-lived assertion with its private key; IAM verifies it against the registered public JWKS. Every
 * negative path (bad signature, wrong audience, expired, replay, missing assertion) must fail closed.
 */
function opensslCnf(): string
{
    // EC keygen via openssl_pkey_new needs an openssl config file on Windows/herd; an empty [req] suffices.
    $cnf = sys_get_temp_dir().DIRECTORY_SEPARATOR.'iam-test-openssl.cnf';
    if (!is_file($cnf)) {
        file_put_contents($cnf, "[req]\n");
    }

    return $cnf;
}

/** @return array{0: string, 1: array<string, mixed>} the private key PEM and its public JWK (kid=k1). */
function pkjwtKeypair(): array
{
    $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1', 'config' => opensslCnf()]);
    openssl_pkey_export($key, $privatePem, null, ['config' => opensslCnf()]);
    $d = openssl_pkey_get_details($key);
    $b64u = static fn (string $b): string => rtrim(strtr(base64_encode($b), '+/', '-_'), '=');

    return [$privatePem, ['kty' => 'EC', 'crv' => 'P-256', 'x' => $b64u($d['ec']['x']), 'y' => $b64u($d['ec']['y']), 'kid' => 'k1', 'use' => 'sig', 'alg' => 'ES256']];
}

/** @param array<string, mixed> $overrides */
function pkjwtAssertion(string $privatePem, string $clientId, string $aud, array $overrides = [], string $kid = 'k1'): string
{
    $now = new DateTimeImmutable;
    $builder = (new Builder(new JoseEncoder, ChainedFormatter::default()))
        ->withHeader('kid', $kid)
        ->issuedBy($overrides['iss'] ?? $clientId)
        ->relatedTo($overrides['sub'] ?? $clientId)
        ->permittedFor($overrides['aud'] ?? $aud)
        ->identifiedBy($overrides['jti'] ?? 'jti-'.bin2hex(random_bytes(8)))
        ->issuedAt($now)
        ->expiresAt($overrides['exp'] ?? $now->modify('+60 seconds'));

    return $builder->getToken(new Sha256, InMemory::plainText($privatePem))->toString();
}

/** @param array<string, mixed> $jwk */
function registerPkjwtClient(array $jwk, array $grants = ['client_credentials']): OauthClient
{
    Organization::query()->firstOrCreate(['key' => 'acme'], ['name' => 'Acme']);
    OauthScope::query()->firstOrCreate(['identifier' => 'stock.read']);

    return OauthClient::query()->create([
        'client_id' => 'cli_pkjwt',
        'name' => 'PKJWT Client',
        'grants' => $grants,
        'scopes' => ['stock.read'],
        'is_confidential' => true,
        'token_endpoint_auth_method' => 'private_key_jwt',
        'jwks' => ['keys' => [$jwk]],
    ]);
}

function postAssertion(string $assertion): TestResponse
{
    return test()->post('/oauth/token', [
        'grant_type' => 'client_credentials',
        'scope' => 'stock.read',
        'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        'client_assertion' => $assertion,
    ]);
}

it('emette un access token con un client_assertion valido (private_key_jwt, nessun secret)', function () {
    [$priv, $jwk] = pkjwtKeypair();
    registerPkjwtClient($jwk);

    $response = postAssertion(pkjwtAssertion($priv, 'cli_pkjwt', url('/oauth/token')));

    $response->assertOk();
    expect($response->json('access_token'))->toBeString()
        ->and($response->json('token_type'))->toBe('Bearer');
});

it('rifiuta un assertion firmato con una chiave diversa (firma non valida)', function () {
    [, $jwk] = pkjwtKeypair();      // la chiave pubblica registrata
    [$otherPriv] = pkjwtKeypair();  // ma firmiamo con un'ALTRA privata
    registerPkjwtClient($jwk);

    postAssertion(pkjwtAssertion($otherPriv, 'cli_pkjwt', url('/oauth/token')))->assertStatus(401);
});

it('rifiuta un assertion con aud sbagliato (minted per un altro endpoint)', function () {
    [$priv, $jwk] = pkjwtKeypair();
    registerPkjwtClient($jwk);

    postAssertion(pkjwtAssertion($priv, 'cli_pkjwt', 'https://evil.example/token'))->assertStatus(401);
});

it('rifiuta un assertion scaduto', function () {
    [$priv, $jwk] = pkjwtKeypair();
    registerPkjwtClient($jwk);

    $expired = pkjwtAssertion($priv, 'cli_pkjwt', url('/oauth/token'), ['exp' => (new DateTimeImmutable)->modify('-10 seconds')]);
    postAssertion($expired)->assertStatus(401);
});

it('rifiuta il replay dello stesso jti (single-use)', function () {
    [$priv, $jwk] = pkjwtKeypair();
    registerPkjwtClient($jwk);

    $assertion = pkjwtAssertion($priv, 'cli_pkjwt', url('/oauth/token'), ['jti' => 'fixed-jti-123']);
    postAssertion($assertion)->assertOk();      // primo uso: ok
    postAssertion($assertion)->assertStatus(401); // replay: rifiutato
});

it('rifiuta una richiesta senza assertion su un client private_key_jwt (nessun secret vale)', function () {
    [, $jwk] = pkjwtKeypair();
    registerPkjwtClient($jwk);

    // Nessun assertion, prova col solo client_id (+ un secret qualsiasi) → fail-closed.
    test()->post('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => 'cli_pkjwt',
        'client_secret' => 'anything',
    ])->assertStatus(401);
});

it('il manifest onboarda un client private_key_jwt (jwks registrato, nessun secret)', function () {
    [, $jwk] = pkjwtKeypair();
    $registry = app(ManifestRegistry::class);
    $manifest = $registry->submit([
        'schema' => 'laravel-iam.manifest.v2',
        'app' => ['key' => 'svc', 'name' => 'Svc', 'type' => 'service', 'risk_level' => 'low'],
        'auth' => ['client_type' => 'confidential', 'token_endpoint_auth_method' => 'private_key_jwt', 'jwks' => ['keys' => [$jwk]]],
        'permissions' => [['key' => 'stock.read', 'risk' => 'low']],
        'roles' => [],
    ], 'test');
    $registry->approve($manifest, 'test');
    $registry->apply($manifest);

    $client = OauthClient::query()->where('client_id', 'cli_svc')->firstOrFail();
    expect($client->usesPrivateKeyJwt())->toBeTrue()
        ->and($client->jwks['keys'][0]['kid'] ?? null)->toBe('k1')
        ->and($client->secret)->toBeNull(); // private_key_jwt → nessun secret condiviso
});

it('la discovery pubblicizza private_key_jwt', function () {
    $this->get('/.well-known/openid-configuration')
        ->assertOk()
        ->assertJsonFragment(['token_endpoint_auth_signing_alg_values_supported' => ['ES256']]);

    expect($this->get('/.well-known/openid-configuration')->json('token_endpoint_auth_methods_supported'))
        ->toContain('private_key_jwt');
});
