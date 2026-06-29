<?php

declare(strict_types=1);

use Illuminate\Auth\GenericUser;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Padosoft\Iam\Contracts\Crypto\TokenSigner;
use Padosoft\Iam\Domain\Identity\Models\User;
use Padosoft\Iam\Domain\OAuth\Models\OauthClient;
use Padosoft\Iam\Domain\OAuth\Models\OauthScope;
use Padosoft\Iam\Domain\Organizations\Models\Organization;
use Tests\TestCase;

uses(RefreshDatabase::class);

/** Registra un client OIDC (scope openid/profile/email) e ritorna lo User IAM target. */
function oidcSetup(): User
{
    $org = Organization::query()->create(['key' => 'acme', 'name' => 'Acme']);
    foreach (['openid', 'profile', 'email', 'stock.read'] as $s) {
        OauthScope::query()->create(['identifier' => $s]);
    }
    OauthClient::register([
        'client_id' => 'cli_oidc',
        'name' => 'OIDC App',
        'grants' => ['authorization_code', 'refresh_token'],
        'scopes' => ['openid', 'profile', 'email'],
        'redirect_uris' => [REDIRECT_URI],
        'is_confidential' => false,
        'is_first_party' => true,
        'organization_id' => $org->id,
    ], null);

    $user = new User;
    $user->forceFill(['name' => 'Mario Rossi', 'email' => 'mario@acme.test', 'email_verified_at' => now()])->save();

    return $user;
}

/** Esegue il flusso auth code per il client OIDC e ritorna l'access token. */
function oidcAccessToken(TestCase $test, string $userId): string
{
    $pkce = pkcePair();
    $location = $test->actingAs(new GenericUser(['id' => $userId]))
        ->get('/oauth/authorize?'.authorizeQuery($pkce['challenge'], [
            'client_id' => 'cli_oidc',
            'scope' => 'openid profile email',
        ]))->headers->get('Location') ?? '';

    $json = $test->post('/oauth/token', [
        'grant_type' => 'authorization_code',
        'client_id' => 'cli_oidc',
        'redirect_uri' => REDIRECT_URI,
        'code' => codeFromRedirect($location),
        'code_verifier' => $pkce['verifier'],
    ])->json();

    return is_array($json) && is_string($json['access_token'] ?? null) ? $json['access_token'] : '';
}

it('espone il discovery OIDC con endpoint, scope e algoritmi', function () {
    oidcSetup();

    $doc = $this->get('/.well-known/openid-configuration');

    $doc->assertOk();
    expect($doc->json('issuer'))->toBeString()
        ->and($doc->json('token_endpoint'))->toContain('/oauth/token')
        ->and($doc->json('authorization_endpoint'))->toContain('/oauth/authorize')
        ->and($doc->json('jwks_uri'))->toContain('/.well-known/jwks.json')
        ->and($doc->json('userinfo_endpoint'))->toContain('/oidc/userinfo')
        ->and($doc->json('scopes_supported'))->toContain('openid')
        ->and($doc->json('response_types_supported'))->toContain('code')
        ->and($doc->json('code_challenge_methods_supported'))->toContain('S256')
        ->and($doc->json('id_token_signing_alg_values_supported'))->toContain('ES256');
});

it('espone il JWKS con le chiavi pubbliche attive (EC P-256)', function () {
    $user = oidcSetup();
    oidcAccessToken($this, $user->id); // forza la creazione della chiave di firma

    $jwks = $this->get('/.well-known/jwks.json');

    $jwks->assertOk();
    expect($jwks->json('keys'))->toBeArray()->not->toBeEmpty()
        ->and($jwks->json('keys.0.kty'))->toBe('EC')
        ->and($jwks->json('keys.0.crv'))->toBe('P-256')
        ->and($jwks->json('keys.0.use'))->toBe('sig');
});

it('userinfo ritorna i claim del subject coperti dagli scope concessi', function () {
    $user = oidcSetup();
    $token = oidcAccessToken($this, $user->id);
    expect($token)->not->toBe('');

    $userinfo = $this->withHeader('Authorization', "Bearer {$token}")->get('/oidc/userinfo');

    $userinfo->assertOk();
    expect($userinfo->json('sub'))->toBe($user->id)
        ->and($userinfo->json('name'))->toBe('Mario Rossi')
        ->and($userinfo->json('email'))->toBe('mario@acme.test')
        ->and($userinfo->json('email_verified'))->toBeTrue();
});

it('emette un id_token OIDC firmato con sub/aud/nonce/auth_time quando scope include openid', function () {
    $user = oidcSetup();
    $pkce = pkcePair();

    $location = $this->actingAs(new GenericUser(['id' => $user->id]))
        ->get('/oauth/authorize?'.authorizeQuery($pkce['challenge'], [
            'client_id' => 'cli_oidc',
            'scope' => 'openid profile',
            'nonce' => 'n-abc123',
        ]))->headers->get('Location') ?? '';

    $token = $this->post('/oauth/token', [
        'grant_type' => 'authorization_code',
        'client_id' => 'cli_oidc',
        'redirect_uri' => REDIRECT_URI,
        'code' => codeFromRedirect($location),
        'code_verifier' => $pkce['verifier'],
    ]);

    $token->assertOk();
    expect($token->json('id_token'))->toBeString();

    $idClaims = app(TokenSigner::class)->parse($token->json('id_token'));
    expect($idClaims['sub'])->toBe($user->id)
        ->and($idClaims['aud'])->toContain('cli_oidc')
        ->and($idClaims['nonce'])->toBe('n-abc123')
        ->and($idClaims['auth_time'])->toBeInt()
        ->and($idClaims['iss'])->toBeString();
});

it('sul refresh l\'id_token mantiene l\'auth_time originale (no max_age bypass) e omette il nonce', function () {
    $user = oidcSetup();
    $pkce = pkcePair();

    $location = $this->actingAs(new GenericUser(['id' => $user->id]))
        ->get('/oauth/authorize?'.authorizeQuery($pkce['challenge'], [
            'client_id' => 'cli_oidc',
            'scope' => 'openid',
            'nonce' => 'n-1',
        ]))->headers->get('Location') ?? '';

    $initial = $this->post('/oauth/token', [
        'grant_type' => 'authorization_code',
        'client_id' => 'cli_oidc',
        'redirect_uri' => REDIRECT_URI,
        'code' => codeFromRedirect($location),
        'code_verifier' => $pkce['verifier'],
    ]);
    $authTime0 = app(TokenSigner::class)->parse($initial->json('id_token'))['auth_time'];
    $refreshToken = $initial->json('refresh_token');

    // Avanza il tempo: se auth_time fosse rigenerato sarebbe now()+10m, non l'originale.
    $this->travel(10)->minutes();

    $refreshed = $this->post('/oauth/token', [
        'grant_type' => 'refresh_token',
        'client_id' => 'cli_oidc',
        'refresh_token' => $refreshToken,
        'scope' => 'openid',
    ]);

    $refreshed->assertOk();
    expect($refreshed->json('id_token'))->toBeString();
    $claims = app(TokenSigner::class)->parse($refreshed->json('id_token'));
    expect($claims['auth_time'])->toBe($authTime0)
        ->and($claims)->not->toHaveKey('nonce');
});

it('non emette id_token per token senza scope openid (client_credentials)', function () {
    $org = Organization::query()->create(['key' => 'acme', 'name' => 'Acme']);
    OauthScope::query()->create(['identifier' => 'stock.read']);
    OauthClient::register([
        'client_id' => 'cli_svc',
        'name' => 'Service',
        'grants' => ['client_credentials'],
        'scopes' => ['stock.read'],
        'is_confidential' => true,
        'organization_id' => $org->id,
    ], 's3cret-value');

    $token = $this->post('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => 'cli_svc',
        'client_secret' => 's3cret-value',
        'scope' => 'stock.read',
    ]);

    $token->assertOk();
    expect($token->json('id_token'))->toBeNull();
});

it('userinfo rifiuta una richiesta senza Bearer token', function () {
    oidcSetup();

    $this->get('/oidc/userinfo')->assertStatus(401);
});

it('userinfo rifiuta un access token senza scope openid (es. client_credentials)', function () {
    $org = Organization::query()->create(['key' => 'acme', 'name' => 'Acme']);
    OauthScope::query()->create(['identifier' => 'stock.read']);
    OauthClient::register([
        'client_id' => 'cli_svc',
        'name' => 'Service',
        'grants' => ['client_credentials'],
        'scopes' => ['stock.read'],
        'is_confidential' => true,
        'organization_id' => $org->id,
    ], 's3cret-value');

    $token = $this->post('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => 'cli_svc',
        'client_secret' => 's3cret-value',
        'scope' => 'stock.read',
    ])->json('access_token');

    $this->withHeader('Authorization', "Bearer {$token}")->get('/oidc/userinfo')->assertStatus(403);
});
