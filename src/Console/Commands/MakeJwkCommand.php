<?php

declare(strict_types=1);

namespace Padosoft\Iam\Console\Commands;

use Illuminate\Console\Command;

/**
 * Convert an EC P-256 PUBLIC key (PEM) into a JWK for private_key_jwt registration — so you never hand-compute
 * the x/y coordinates. Print a single JWK (default) or a full `{ "keys": [...] }` set (--jwks) ready to paste
 * into a manifest's `auth.jwks`. Reads only the PUBLIC key; the private key never leaves the app.
 */
final class MakeJwkCommand extends Command
{
    protected $signature = 'iam:jwk
        {pem : path to a PUBLIC key PEM file (EC P-256 / ES256)}
        {--kid= : key id to embed (default: a short hash of the key)}
        {--jwks : wrap the key in a full {"keys":[...]} set}';

    protected $description = 'Convert an EC P-256 public key PEM into a JWK (for private_key_jwt registration).';

    public function handle(): int
    {
        $path = $this->argument('pem');
        if (!is_string($path) || !is_file($path)) {
            $this->error('File not found: '.(is_string($path) ? $path : ''));

            return self::FAILURE;
        }

        $key = openssl_pkey_get_public((string) file_get_contents($path));
        if ($key === false) {
            $this->error('Not a valid PUBLIC key PEM. Export one with: openssl ec -in private.pem -pubout -out public.pem');

            return self::FAILURE;
        }

        $d = openssl_pkey_get_details($key);
        $ec = is_array($d) && isset($d['ec']) && is_array($d['ec']) ? $d['ec'] : null;
        if ($ec === null
            || ($d['type'] ?? null) !== OPENSSL_KEYTYPE_EC
            || ($ec['curve_name'] ?? null) !== 'prime256v1'
            || !is_string($ec['x'] ?? null) || !is_string($ec['y'] ?? null)) {
            $this->error('Only EC P-256 (ES256) public keys are supported.');

            return self::FAILURE;
        }

        $b64u = static fn (string $b): string => rtrim(strtr(base64_encode($b), '+/', '-_'), '=');
        $x = $b64u($ec['x']);
        $y = $b64u($ec['y']);
        $kidOpt = $this->option('kid');
        $kid = is_string($kidOpt) && $kidOpt !== '' ? $kidOpt : substr(sha1($x.$y), 0, 8);

        $jwk = ['kty' => 'EC', 'crv' => 'P-256', 'x' => $x, 'y' => $y, 'kid' => $kid, 'alg' => 'ES256', 'use' => 'sig'];
        $out = $this->option('jwks') === true ? ['keys' => [$jwk]] : $jwk;

        $this->line((string) json_encode($out, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

        return self::SUCCESS;
    }
}
