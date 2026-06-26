<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Crypto;

use Padosoft\Iam\Contracts\Crypto\KeyProvider;

/**
 * KeyProvider locale (v1, default): wrap/unwrap delle DEK con una KEK simmetrica
 * (libsodium secretbox = XSalsa20-Poly1305, autenticato). Chiavi di firma JWT in M4.
 *
 * Vedi laravel-iam-docs/11-crypto-and-key-management.md §5.
 */
final class LocalKeyProvider implements KeyProvider
{
    private const KEY_ID = 'local-kek';

    public function __construct(private readonly string $kek)
    {
        if (strlen($this->kek) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
            throw new \InvalidArgumentException(
                'La KEK locale deve essere di '.SODIUM_CRYPTO_SECRETBOX_KEYBYTES.' byte (config iam.crypto.kek, base64).'
            );
        }
    }

    public function wrapDataKey(string $plaintextDek): array
    {
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $box = sodium_crypto_secretbox($plaintextDek, $nonce, $this->kek);

        return ['ciphertext' => base64_encode($nonce.$box), 'key_id' => self::KEY_ID, 'key_version' => 1];
    }

    public function unwrapDataKey(array $wrapped): string
    {
        $raw = base64_decode($wrapped['ciphertext'], true);
        if ($raw === false || strlen($raw) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) {
            throw new \RuntimeException('Wrapped DEK non valida.');
        }
        $nonce = substr($raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $box = substr($raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $dek = sodium_crypto_secretbox_open($box, $nonce, $this->kek);
        if ($dek === false) {
            throw new \RuntimeException('Unwrap DEK fallito (KEK errata o dato manomesso).');
        }

        return $dek;
    }

    public function generateDataKey(): array
    {
        $dek = sodium_crypto_secretbox_keygen();

        return ['plaintext' => $dek, 'wrapped' => $this->wrapDataKey($dek)];
    }

    // --- Firma JWT/JWKS: M4 (con lcobucci/jwt + chiavi asimmetriche ES256). ---

    public function sign(string $payload): array
    {
        throw new \RuntimeException('sign(): chiavi di firma token in M4 (OAuth/OIDC).');
    }

    public function verify(string $payload, string $signature, string $kid): bool
    {
        throw new \RuntimeException('verify(): M4.');
    }

    public function activeSigningKey(): array
    {
        throw new \RuntimeException('activeSigningKey(): M4.');
    }

    public function publishableJwks(): array
    {
        throw new \RuntimeException('publishableJwks(): M4.');
    }

    public function rotateSigningKey(): array
    {
        throw new \RuntimeException('rotateSigningKey(): M4.');
    }
}
