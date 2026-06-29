<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Testing\TestResponse;
use Padosoft\Iam\Contracts\Crypto\TokenSigner;
use Padosoft\Iam\Domain\OAuth\Models\OauthAccessToken;
use Padosoft\Iam\Domain\OAuth\Models\OauthRefreshToken;
use Padosoft\Iam\Domain\OAuth\Models\OauthTokenChain;
use Padosoft\Iam\Domain\OAuth\Repositories\RefreshTokenRepository;
use Tests\TestCase;

uses(RefreshDatabase::class);

function refresh(TestCase $test, string $refreshToken): TestResponse
{
    return $test->post('/oauth/token', [
        'grant_type' => 'refresh_token',
        'client_id' => 'cli_app',
        'refresh_token' => $refreshToken,
    ]);
}

it('ruota il refresh token ed emette nuovi token, revocando il vecchio access token', function () {
    authCodeClient();
    $tokens = obtainTokensViaAuthCode($this);
    $oldJti = app(TokenSigner::class)->parse($tokens['access_token'])['jti'];

    $rotated = refresh($this, $tokens['refresh_token']);

    $rotated->assertOk();
    expect($rotated->json('access_token'))->toBeString()
        ->and($rotated->json('refresh_token'))->toBeString()
        ->and($rotated->json('access_token'))->not->toBe($tokens['access_token'])
        ->and($rotated->json('refresh_token'))->not->toBe($tokens['refresh_token']);

    // Rotation: il vecchio access token è revocato nel ledger.
    expect(OauthAccessToken::query()->where('jti', $oldJti)->where('revoked', true)->exists())->toBeTrue();
});

it('il riuso (replay) di un refresh token già ruotato revoca l\'intera catena (RFC 9700)', function () {
    authCodeClient();
    $tokens = obtainTokensViaAuthCode($this);
    $r1 = $tokens['refresh_token'];

    // Prima rotazione legittima: R1 → R2.
    $rotated = refresh($this, $r1);
    $rotated->assertOk();
    $r2 = $rotated->json('refresh_token');

    // Replay di R1 (ormai ruotato/revocato) → rifiutato (invalid_refresh_token = 400).
    refresh($this, $r1)->assertStatus(400);

    // Effetto chain-revoke: anche R2, che era valido, è ora revocato → inutilizzabile.
    refresh($this, $r2)->assertStatus(400);

    // La catena risulta marcata come compromessa.
    $chainId = OauthRefreshToken::query()->value('chain_id');
    expect(OauthTokenChain::query()->whereKey($chainId)->where('compromised', true)->exists())->toBeTrue();
});

it('isRefreshTokenRevoked è chain-aware: token non-revocato in catena compromessa = revocato', function () {
    // Simula il caso race: un token figlio la cui RIGA non è (ancora) revocata, ma la cui catena
    // è compromessa, deve risultare comunque revocato (born-dead).
    OauthTokenChain::query()->create(['chain_id' => 'chainX', 'compromised' => true]);
    OauthRefreshToken::query()->create([
        'refresh_token_id' => 'rt_child',
        'chain_id' => 'chainX',
        'access_token_jti' => 'jti_child',
        'revoked' => false,
    ]);

    expect(app(RefreshTokenRepository::class)->isRefreshTokenRevoked('rt_child'))->toBeTrue();
});

it('claimForRotation transiziona il token una sola volta (claim atomico, single-winner)', function () {
    authCodeClient();
    obtainTokensViaAuthCode($this);
    $rid = OauthRefreshToken::query()->value('refresh_token_id');
    expect($rid)->toBeString();

    $repo = app(RefreshTokenRepository::class);

    // Il primo claim vince (active→revoked); il secondo perde (già revocato) → niente doppia rotazione.
    expect($repo->claimForRotation($rid))->toBeTrue()
        ->and($repo->claimForRotation($rid))->toBeFalse();
});

it('un refresh token valido non ancora ruotato funziona una sola volta', function () {
    authCodeClient();
    $tokens = obtainTokensViaAuthCode($this);

    refresh($this, $tokens['refresh_token'])->assertOk();
    // Secondo uso dello stesso (ora revocato) → rifiutato (invalid_refresh_token = 400).
    refresh($this, $tokens['refresh_token'])->assertStatus(400);
});
