<?php

declare(strict_types=1);

use Illuminate\Auth\GenericUser;
use Padosoft\Iam\Domain\OAuth\Models\OauthClient;
use Padosoft\Iam\Domain\OAuth\Models\OauthScope;
use Padosoft\Iam\Domain\Organizations\Models\Organization;
use Tests\TestCase;

/**
 * Helper condivisi dai test OAuth (Authorization Code, Refresh Token).
 */
if (!defined('REDIRECT_URI')) {
    define('REDIRECT_URI', 'https://app.test/callback');
}

/**
 * @param  list<string>  $grants
 */
function authCodeClient(bool $confidential = false, array $grants = ['authorization_code', 'refresh_token'], bool $firstParty = true): OauthClient
{
    $org = Organization::query()->create(['key' => 'acme', 'name' => 'Acme']);
    OauthScope::query()->create(['identifier' => 'stock.read']);

    return OauthClient::register([
        'client_id' => 'cli_app',
        'name' => 'SPA',
        'grants' => $grants,
        'scopes' => ['stock.read'],
        'redirect_uris' => [REDIRECT_URI],
        'is_confidential' => $confidential,
        'is_first_party' => $firstParty,
        'organization_id' => $org->id,
    ], $confidential ? 's3cret-value' : null);
}

/** @return array{verifier: string, challenge: string} */
function pkcePair(): array
{
    $verifier = 'verifier-'.str_repeat('a', 50); // 43..128 char, caratteri unreserved
    $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');

    return ['verifier' => $verifier, 'challenge' => $challenge];
}

/** @param array<string, string> $overrides */
function authorizeQuery(string $challenge, array $overrides = []): string
{
    return http_build_query(array_merge([
        'response_type' => 'code',
        'client_id' => 'cli_app',
        'redirect_uri' => REDIRECT_URI,
        'scope' => 'stock.read',
        'state' => 'state-xyz',
        'code_challenge' => $challenge,
        'code_challenge_method' => 'S256',
    ], $overrides));
}

function codeFromRedirect(string $location): string
{
    $query = parse_url($location, PHP_URL_QUERY);
    parse_str(is_string($query) ? $query : '', $params);
    $code = $params['code'] ?? '';

    return is_string($code) ? $code : '';
}

/**
 * Esegue il flusso Authorization Code + PKCE e ritorna la token response (access + refresh).
 *
 * @return array<string, mixed>
 */
function obtainTokensViaAuthCode(TestCase $test, string $userId = 'usr_123'): array
{
    $pkce = pkcePair();
    $location = $test->actingAs(new GenericUser(['id' => $userId]))
        ->get('/oauth/authorize?'.authorizeQuery($pkce['challenge']))
        ->headers->get('Location') ?? '';

    $json = $test->post('/oauth/token', [
        'grant_type' => 'authorization_code',
        'client_id' => 'cli_app',
        'redirect_uri' => REDIRECT_URI,
        'code' => codeFromRedirect($location),
        'code_verifier' => $pkce['verifier'],
    ])->json();

    return is_array($json) ? $json : [];
}
