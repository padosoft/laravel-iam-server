<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Artisan;

uses(RefreshDatabase::class);

it('iam:jwk converts an EC P-256 public PEM into a JWK', function () {
    $cnf = sys_get_temp_dir().DIRECTORY_SEPARATOR.'iam-test-openssl.cnf';
    if (!is_file($cnf)) {
        file_put_contents($cnf, "[req]\n");
    }
    $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1', 'private_key_bits' => 2048, 'config' => $cnf]);
    $details = openssl_pkey_get_details($key);
    $path = sys_get_temp_dir().DIRECTORY_SEPARATOR.'iam-pub-'.bin2hex(random_bytes(4)).'.pem';
    file_put_contents($path, $details['key']); // the public key PEM

    $code = Artisan::call('iam:jwk', ['pem' => $path, '--kid' => 'k1']);
    $jwk = json_decode(trim(Artisan::output()), true);
    @unlink($path);

    expect($code)->toBe(0)
        ->and($jwk['kty'])->toBe('EC')
        ->and($jwk['crv'])->toBe('P-256')
        ->and($jwk['kid'])->toBe('k1')
        ->and($jwk['alg'])->toBe('ES256')
        ->and(strlen((string) base64_decode(strtr($jwk['x'], '-_', '+/'), true)))->toBe(32); // 32-byte P-256 coord
});

it('iam:jwk left-pads a short coordinate to the full 32 bytes (RFC 7518 §6.2.1.2)', function () {
    // Deterministic regression, on a fixture key whose X really does start with a zero byte.
    // The random-key test above only catches this about once in 256 runs — which is exactly how
    // it got shipped: `openssl_pkey_get_details()` strips leading zeros, so the emitted JWK was
    // 31 bytes and a strict verifier would refuse it, intermittently and unreproducibly.
    $path = __DIR__.'/../../Fixtures/ec-p256-short-x-public.pem';

    $code = Artisan::call('iam:jwk', ['pem' => $path, '--kid' => 'short-x']);
    $jwk = json_decode(trim(Artisan::output()), true);

    $x = (string) base64_decode(strtr($jwk['x'], '-_', '+/'), true);

    expect($code)->toBe(0)
        ->and(strlen($x))->toBe(32)
        ->and($x[0])->toBe("\x00"); // il byte che OpenSSL aveva tolto

    // La coppia y resta comunque a 32 byte: il padding non deve allungare ciò che è già pieno.
    expect(strlen((string) base64_decode(strtr($jwk['y'], '-_', '+/'), true)))->toBe(32);
});

it('iam:jwk fails on a missing file', function () {
    test()->artisan('iam:jwk', ['pem' => 'C:/does/not/exist.pem'])->assertExitCode(1);
});
