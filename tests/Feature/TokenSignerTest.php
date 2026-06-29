<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Padosoft\Iam\Contracts\Crypto\KeyProvider;
use Padosoft\Iam\Contracts\Crypto\TokenSigner;
use Padosoft\Iam\Domain\OAuth\Models\SigningKey;
use Padosoft\Iam\Domain\OAuth\Token\LocalTokenSigner;

uses(RefreshDatabase::class);

function signer(): TokenSigner
{
    return app(TokenSigner::class);
}

function signerForIssuer(string $issuer): TokenSigner
{
    $cnf = config('iam.crypto.openssl_config');

    return new LocalTokenSigner(app(KeyProvider::class), $issuer, is_string($cnf) ? $cnf : null);
}

it('emette e verifica un JWT (round-trip dei claims, incl. policy_version)', function () {
    $jwt = signer()->issue([
        'sub' => 'usr_1', 'aud' => 'warehouse', 'org' => 'org_a', 'policy_version' => 42,
    ], 900);

    $claims = signer()->parse($jwt);

    expect($claims['sub'])->toBe('usr_1')
        ->and($claims['aud'])->toContain('warehouse')
        ->and($claims['policy_version'])->toBe(42)
        ->and($claims['iss'])->toBeString()
        ->and($jwt)->toBeString()->toContain('.');
});

it('genera una chiave attiva al primo uso e la espone nel JWKS (EC P-256)', function () {
    signer()->issue(['sub' => 'x'], 60);

    $jwks = signer()->jwks();

    expect($jwks)->toHaveCount(1)
        ->and($jwks[0]['kty'])->toBe('EC')
        ->and($jwks[0]['crv'])->toBe('P-256')
        ->and($jwks[0]['use'])->toBe('sig')
        ->and($jwks[0])->toHaveKeys(['x', 'y', 'kid', 'alg']);
});

it('rifiuta un token manomesso (firma non valida)', function () {
    $jwt = signer()->issue(['sub' => 'x'], 60);
    $parts = explode('.', $jwt);
    $parts[1] = rtrim(strtr(base64_encode('{"sub":"attacker","iss":"x"}'), '+/', '-_'), '=');

    expect(fn () => signer()->parse(implode('.', $parts)))->toThrow(RuntimeException::class);
});

it('rifiuta un token la cui chiave è stata revocata (kid non valido)', function () {
    $jwt = signer()->issue(['sub' => 'x'], 60);
    SigningKey::query()->update(['revoked_at' => now()]);

    expect(fn () => signer()->parse($jwt))->toThrow(RuntimeException::class);
});

it('non permette al caller di sovrascrivere iss (anti-spoofing)', function () {
    $jwt = signer()->issue(['sub' => 'x', 'iss' => 'https://attacker.evil'], 60);

    expect(signer()->parse($jwt)['iss'])->not->toBe('https://attacker.evil');
});

it('supporta audience multiple (aud come array)', function () {
    $jwt = signer()->issue(['sub' => 'x', 'aud' => ['warehouse', 'billing']], 60);

    $aud = signer()->parse($jwt)['aud'];
    expect($aud)->toContain('warehouse')->toContain('billing');
});

it('rifiuta un token con header kid sostituito (firma non corrisponde)', function () {
    $jwt = signer()->issue(['sub' => 'x'], 60);
    $newKid = signer()->rotate();
    $parts = explode('.', $jwt);
    $parts[0] = rtrim(strtr(base64_encode(json_encode(
        ['alg' => 'ES256', 'typ' => 'JWT', 'kid' => $newKid], JSON_THROW_ON_ERROR
    )), '+/', '-_'), '=');

    expect(fn () => signer()->parse(implode('.', $parts)))->toThrow(RuntimeException::class);
});

it('rifiuta un token emesso da un issuer diverso (anti cross-environment)', function () {
    // 'prod' e 'staging' condividono lo stesso keystore: la firma è valida, ma l'iss no.
    $jwt = signerForIssuer('https://prod.iam')->issue(['sub' => 'x'], 60);

    expect(fn () => signerForIssuer('https://staging.iam')->parse($jwt))->toThrow(RuntimeException::class);
});

it('rotazione: vecchia chiave in overlap, nuova attiva; entrambi i token restano validi', function () {
    $jwt1 = signer()->issue(['sub' => 'x'], 60);
    $newKid = signer()->rotate();
    $jwt2 = signer()->issue(['sub' => 'y'], 60);

    expect(signer()->jwks())->toHaveCount(2)
        ->and(signer()->parse($jwt1)['sub'])->toBe('x')
        ->and(signer()->parse($jwt2)['sub'])->toBe('y')
        ->and(SigningKey::query()->where('kid', $newKid)->where('status', 'active')->exists())->toBeTrue()
        ->and(SigningKey::query()->where('status', 'overlap')->count())->toBe(1);
});
