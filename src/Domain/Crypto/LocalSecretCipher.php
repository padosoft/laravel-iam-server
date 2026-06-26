<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Crypto;

use Padosoft\Iam\Contracts\Crypto\KeyProvider;
use Padosoft\Iam\Contracts\Crypto\SecretCipher;
use Padosoft\Iam\Domain\Crypto\Models\DataKey;

/**
 * Cifratura segreti/PII con envelope encryption (doc 11 §3-§4, §8).
 * - con `scope`: DEK per-scope persistita in iam_data_keys → abilita crypto-shredding GDPR.
 * - senza `scope`: DEK per-valore, incartata e salvata nel valore stesso.
 */
final class LocalSecretCipher implements SecretCipher
{
    public function __construct(private readonly KeyProvider $keys) {}

    public function encrypt(string $plaintext, ?string $scope = null): array
    {
        if ($scope !== null) {
            [$dek, $keyId, $keyVersion] = $this->scopedDekForEncrypt($scope);
            $wrappedDek = null;
        } else {
            $generated = $this->keys->generateDataKey();
            $dek = $generated['plaintext'];
            $wrappedDek = $generated['wrapped']['ciphertext'];
            $keyId = $generated['wrapped']['key_id'];
            $keyVersion = $generated['wrapped']['key_version'];
        }

        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $ciphertext = base64_encode($nonce.sodium_crypto_secretbox($plaintext, $nonce, $dek));
        sodium_memzero($dek);

        return [
            'ciphertext' => $ciphertext,
            'wrapped_dek' => $wrappedDek,
            'key_id' => $keyId,
            'key_version' => $keyVersion,
            'scope' => $scope,
        ];
    }

    public function decrypt(array $value): string
    {
        $scope = $value['scope'];
        if ($scope !== null) {
            $dek = $this->scopedDekForDecrypt($scope);
        } else {
            if ($value['wrapped_dek'] === null) {
                throw new \RuntimeException('wrapped_dek mancante per un valore senza scope.');
            }
            $dek = $this->keys->unwrapDataKey([
                'ciphertext' => $value['wrapped_dek'],
                'key_id' => $value['key_id'],
                'key_version' => $value['key_version'],
            ]);
        }

        $raw = base64_decode($value['ciphertext'], true);
        if ($raw === false || strlen($raw) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) {
            throw new \RuntimeException('Ciphertext non valido.');
        }
        $nonce = substr($raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $box = substr($raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $plaintext = sodium_crypto_secretbox_open($box, $nonce, $dek);
        sodium_memzero($dek);
        if ($plaintext === false) {
            throw new \RuntimeException('Decrypt fallito (dato manomesso o DEK errata).');
        }

        return $plaintext;
    }

    public function shred(string $scope): void
    {
        DataKey::query()->where('scope', $scope)->update([
            'wrapped_dek' => null,
            'shredded_at' => now(),
        ]);
    }

    /**
     * DEK per cifrare nello scope (get-or-create). Fallisce se lo scope è stato shredded.
     *
     * @return array{0: string, 1: string, 2: int} [dek, key_id, key_version]
     */
    private function scopedDekForEncrypt(string $scope): array
    {
        $row = DataKey::query()->where('scope', $scope)->first();

        if ($row !== null && $row->shredded_at !== null) {
            throw new \RuntimeException("Scope {$scope} è stato crypto-shredded: impossibile cifrare nuovi dati.");
        }

        if ($row === null) {
            $generated = $this->keys->generateDataKey();
            DataKey::query()->create([
                'scope' => $scope,
                'wrapped_dek' => $generated['wrapped']['ciphertext'],
                'key_id' => $generated['wrapped']['key_id'],
                'key_version' => $generated['wrapped']['key_version'],
            ]);

            return [$generated['plaintext'], $generated['wrapped']['key_id'], $generated['wrapped']['key_version']];
        }

        $dek = $this->keys->unwrapDataKey([
            'ciphertext' => (string) $row->wrapped_dek,
            'key_id' => $row->key_id,
            'key_version' => $row->key_version,
        ]);

        return [$dek, $row->key_id, $row->key_version];
    }

    private function scopedDekForDecrypt(string $scope): string
    {
        $row = DataKey::query()->where('scope', $scope)->first();

        if ($row === null || $row->shredded_at !== null || $row->wrapped_dek === null) {
            throw new \RuntimeException("Scope {$scope}: DEK assente o crypto-shredded → dato irrecuperabile.");
        }

        return $this->keys->unwrapDataKey([
            'ciphertext' => $row->wrapped_dek,
            'key_id' => $row->key_id,
            'key_version' => $row->key_version,
        ]);
    }
}
