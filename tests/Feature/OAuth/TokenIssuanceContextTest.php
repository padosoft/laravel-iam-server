<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Padosoft\Iam\Contracts\Crypto\TokenSigner;
use Padosoft\Iam\Domain\OAuth\Token\TokenIssuanceContext;

uses(RefreshDatabase::class);

function issuance(): TokenIssuanceContext
{
    return app(TokenIssuanceContext::class);
}

/** @return array<string, mixed> */
function jwtHeader(string $jwt): array
{
    $b64 = explode('.', $jwt)[0];
    $decoded = json_decode(base64_decode(strtr($b64, '-_', '+/')), true);

    return is_array($decoded) ? $decoded : [];
}

it('applica act + pds_dgr + audience override + extra ai claims', function () {
    $ctx = issuance();
    $ctx->setActor(['sub' => 'agent:01J8TEST'], 'dgr_01J9TEST');
    $ctx->setAudience(['mcp://crm-tools']);
    $ctx->addClaim('op', 'anthropic');

    $claims = $ctx->apply(['sub' => 'user:42', 'aud' => 'cli_warehouse', 'scope' => 'orders:read']);

    expect($claims['sub'])->toBe('user:42')                       // MAI toccato
        ->and($claims['act'])->toBe(['sub' => 'agent:01J8TEST'])
        ->and($claims['pds_dgr'])->toBe('dgr_01J9TEST')
        ->and($claims['aud'])->toBe(['mcp://crm-tools'])           // override audience
        ->and($claims['op'])->toBe('anthropic')
        ->and($claims['scope'])->toBe('orders:read');
});

it('rifiuta le chiavi riservate via addClaim (fail-closed, non silenzioso)', function (string $reserved) {
    expect(fn () => issuance()->addClaim($reserved, 'x'))
        ->toThrow(InvalidArgumentException::class);
})->with(['sub', 'iss', 'scope', 'sid', 'aal', 'act', 'pds_dgr', 'aud', 'client_id', 'policy_version']);

it('senza actor non emette act né pds_dgr, e senza audience non tocca aud', function () {
    $claims = issuance()->apply(['sub' => 'user:42', 'aud' => 'cli_warehouse']);

    expect($claims)->not->toHaveKey('act')
        ->and($claims)->not->toHaveKey('pds_dgr')
        ->and($claims['aud'])->toBe('cli_warehouse');
});

it('reset azzera tutto lo stato (Octane-safe come OidcContext)', function () {
    $ctx = issuance();
    $ctx->setActor(['sub' => 'agent:01J8TEST'], 'dgr_x');
    $ctx->setAudience(['mcp://x']);
    $ctx->setTyp('delegated+jwt');
    $ctx->addClaim('op', 'anthropic');

    $ctx->reset();

    $claims = $ctx->apply(['sub' => 'user:42', 'aud' => 'cli_warehouse']);
    expect($claims)->toBe(['sub' => 'user:42', 'aud' => 'cli_warehouse'])
        ->and($ctx->typ())->toBeNull();
});

it('il signer emette l\'header typ quando impostato (token delegati)', function () {
    issuance()->setTyp('delegated+jwt');

    $jwt = app(TokenSigner::class)->issue(['sub' => 'user:42', 'aud' => 'mcp://crm'], 300);

    expect(jwtHeader($jwt)['typ'] ?? null)->toBe('delegated+jwt');
});

it('senza typ impostato l\'header resta il default (nessuna regressione sui token normali)', function () {
    $jwt = app(TokenSigner::class)->issue(['sub' => 'user:42', 'aud' => 'cli_x'], 300);

    expect(jwtHeader($jwt)['typ'] ?? null)->not->toBe('delegated+jwt');
});

it('l\'actor claim vuoto è rifiutato', function () {
    expect(fn () => issuance()->setActor([]))
        ->toThrow(InvalidArgumentException::class);
});
