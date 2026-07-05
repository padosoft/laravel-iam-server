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

it('iam:jwk fails on a missing file', function () {
    test()->artisan('iam:jwk', ['pem' => 'C:/does/not/exist.pem'])->assertExitCode(1);
});
