<?php

declare(strict_types=1);

use Illuminate\Auth\GenericUser;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Padosoft\Iam\Contracts\Crypto\TokenSigner;

uses(RefreshDatabase::class);

it('completa il flusso Authorization Code + PKCE (public client) fino agli access/refresh token', function () {
    authCodeClient();
    $pkce = pkcePair();

    $authorize = $this->actingAs(new GenericUser(['id' => 'usr_123']))
        ->get('/oauth/authorize?'.authorizeQuery($pkce['challenge']));

    $authorize->assertRedirect();
    $location = $authorize->headers->get('Location') ?? '';
    expect($location)->toStartWith(REDIRECT_URI);

    $code = codeFromRedirect($location);
    expect($code)->not->toBe('');

    $token = $this->post('/oauth/token', [
        'grant_type' => 'authorization_code',
        'client_id' => 'cli_app',
        'redirect_uri' => REDIRECT_URI,
        'code' => $code,
        'code_verifier' => $pkce['verifier'],
    ]);

    $token->assertOk();
    expect($token->json('access_token'))->toBeString()
        ->and($token->json('refresh_token'))->toBeString();

    $claims = app(TokenSigner::class)->parse($token->json('access_token'));
    expect($claims['sub'])->toBe('usr_123')
        ->and($claims['client_id'])->toBe('cli_app')
        ->and($claims['scope'])->toBe('stock.read');
});

it('rifiuta lo scambio del code senza code_verifier (PKCE obbligatorio)', function () {
    authCodeClient();
    $pkce = pkcePair();

    $location = $this->actingAs(new GenericUser(['id' => 'usr_123']))
        ->get('/oauth/authorize?'.authorizeQuery($pkce['challenge']))
        ->headers->get('Location') ?? '';
    $code = codeFromRedirect($location);

    $this->post('/oauth/token', [
        'grant_type' => 'authorization_code',
        'client_id' => 'cli_app',
        'redirect_uri' => REDIRECT_URI,
        'code' => $code,
        // code_verifier mancante
    ])->assertStatus(400);
});

it('rifiuta code_challenge_method diverso da S256 (no downgrade a plain)', function () {
    authCodeClient();
    $pkce = pkcePair();

    $this->actingAs(new GenericUser(['id' => 'usr_123']))
        ->get('/oauth/authorize?'.authorizeQuery($pkce['challenge'], ['code_challenge_method' => 'plain']))
        ->assertStatus(400);
});

it('rifiuta una redirect_uri non registrata (no open redirect)', function () {
    authCodeClient();
    $pkce = pkcePair();

    // redirect_uri non registrata → league NON redirige verso di essa (4xx diretto).
    $this->actingAs(new GenericUser(['id' => 'usr_123']))
        ->get('/oauth/authorize?'.authorizeQuery($pkce['challenge'], ['redirect_uri' => 'https://evil.test/steal']))
        ->assertStatus(401);
});

it('senza utente autenticato non emette code (login gating)', function () {
    authCodeClient();
    $pkce = pkcePair();

    // Nessun actingAs → 401 (login = M5).
    $this->get('/oauth/authorize?'.authorizeQuery($pkce['challenge']))->assertStatus(401);
});

it('un client third-party NON ottiene consenso implicito (secure default)', function () {
    authCodeClient(firstParty: false); // third-party
    $pkce = pkcePair();

    $response = $this->actingAs(new GenericUser(['id' => 'usr_123']))
        ->get('/oauth/authorize?'.authorizeQuery($pkce['challenge']));

    // Niente consenso implicito → redirect con error=access_denied, nessun code.
    $response->assertRedirect();
    $location = $response->headers->get('Location') ?? '';
    expect($location)->toContain('error=access_denied')
        ->and(codeFromRedirect($location))->toBe('');
});
