<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Carbon;
use Padosoft\Iam\Contracts\Crypto\TokenSigner;
use Padosoft\Iam\Domain\Identity\Models\Session;
use Padosoft\Iam\Domain\OAuth\Entities\AccessTokenEntity;
use Padosoft\Iam\Domain\OAuth\Entities\ClientEntity;
use Padosoft\Iam\Domain\OAuth\Oidc\OidcContext;
use Padosoft\Iam\Domain\OAuth\Token\AccessTokenClaims;

uses(RefreshDatabase::class);

/**
 * IAM-19 (review round on PR #25): the step-up FRESHNESS window must be re-applied when the access token's
 * AAL claim is minted. Otherwise a refresh re-stamps a fresh `aal2` from a stale elevation and the Admin
 * gate (which trusts the token's `aal`) would honour a step-up far past its window — a perpetual renewal.
 * This mirrors NativeAssuranceProvider::currentAal, verified here at the token-mint seam.
 *
 * @return array<string, mixed>
 */
function buildAccessTokenClaimsForSession(string $sid): array
{
    $oidc = new OidcContext;
    $oidc->setSession($sid, 'aal2', []);

    $claims = new AccessTokenClaims($oidc);
    $token = new AccessTokenEntity(app(TokenSigner::class), $claims);
    $token->setClient(new ClientEntity('cli_1', 'Demo', 'https://app.example', true));
    $token->setUserIdentifier('usr_1');
    $token->setIdentifier('tok_1');

    return $claims->build($token);
}

it('stamps the elevated AAL while the step-up is still fresh', function () {
    $session = Session::query()->create(['user_id' => 'usr_1', 'aal' => 'aal2']);
    $session->forceFill(['step_up_at' => Carbon::now()->subMinutes(5)])->save(); // within the 900s window

    expect(buildAccessTokenClaimsForSession($session->getKey())['aal'])->toBe('aal2');
});

it('downgrades a STALE step-up elevation to aal1 at mint (refresh cannot renew it forever)', function () {
    $session = Session::query()->create(['user_id' => 'usr_1', 'aal' => 'aal2']);
    $session->forceFill(['step_up_at' => Carbon::now()->subMinutes(30)])->save(); // past the 900s window

    expect(buildAccessTokenClaimsForSession($session->getKey())['aal'])->toBe('aal1');
});

it('never expires an initial-auth AAL2 (no step_up_at recorded)', function () {
    // aal2 with no step_up_at = the level of the INITIAL authentication (e.g. passkey login), not a
    // step-up elevation, so the freshness window does not apply.
    $session = Session::query()->create(['user_id' => 'usr_1', 'aal' => 'aal2']);

    expect(buildAccessTokenClaimsForSession($session->getKey())['aal'])->toBe('aal2');
});

it('freshness disabled (window <= 0) keeps a stale elevation', function () {
    config()->set('iam.authentication.session.step_up_freshness', 0);
    $session = Session::query()->create(['user_id' => 'usr_1', 'aal' => 'aal2']);
    $session->forceFill(['step_up_at' => Carbon::now()->subDays(1)])->save();

    expect(buildAccessTokenClaimsForSession($session->getKey())['aal'])->toBe('aal2');
});
