<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Crypto;

use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;
use Padosoft\Iam\Contracts\Crypto\KeyProvider;
use Padosoft\Iam\Contracts\Crypto\SecretCipher;
use Padosoft\Iam\Domain\Crypto\Models\DataKey;

/**
 * Cifratura segreti/PII con envelope encryption (doc 11 §3-§4, §8).
 * - con `scope`: DEK per-scope in iam_data_keys → crypto-shredding GDPR.
 * - senza `scope`: DEK per-valore, incartata nel valore stesso.
 *
 * Concorrenza: per lo scope, l'INTERA cifratura avviene dentro una transazione con
 * lockForUpdate sulla riga DEK → il lock è tenuto fino a dopo `sodium_crypto_secretbox`,
 * quindi uno `shred()` concorrente (UPDATE sulla stessa riga) attende il commit:
 * niente ciphertext prodotto con una DEK già distrutta (no silent data loss post-shred).
 */
final class LocalSecretCipher implements SecretCipher
{
    public function __construct(private readonly KeyProvider $keys) {}

    public function encrypt(string $plaintext, ?string $scope = null): array
    {
        return $scope === null
            ? $this->encryptWithFreshDek($plaintext)
            : $this->encryptScoped($plaintext, $scope);
    }

    /** @return array{ciphertext: string, wrapped_dek: string|null, key_id: string, key_version: int, scope: string|null} */
    private function encryptScoped(string $plaintext, string $scope): array
    {
        $ciphertext = '';
        $keyId = '';
        $keyVersion = 0;

        // L'INTERA cifratura sta nella transazione: il lock sulla riga DEK è tenuto fino al
        // commit, quindi uno shred() concorrente attende → niente ciphertext con DEK distrutta.
        DB::transaction(function () use ($plaintext, $scope, &$ciphertext, &$keyId, &$keyVersion): void {
            [$dek, $kid, $kver] = $this->lockedScopedDek($scope);
            $ciphertext = $this->seal($plaintext, $dek);
            $keyId = $kid;
            $keyVersion = $kver;
        });

        return [
            'ciphertext' => $ciphertext,
            'wrapped_dek' => null,
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

        try {
            $raw = base64_decode($value['ciphertext'], true);
            if ($raw === false || strlen($raw) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) {
                throw new \RuntimeException('Ciphertext non valido.');
            }
            $nonce = substr($raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
            $box = substr($raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
            $plaintext = sodium_crypto_secretbox_open($box, $nonce, $dek);
        } finally {
            sodium_memzero($dek);
        }

        if ($plaintext === false) {
            throw new \RuntimeException('Decrypt fallito (dato manomesso o DEK errata).');
        }

        return $plaintext;
    }

    /**
     * Crypto-shredding GDPR: distrugge la DEK dello scope (idempotente). TODO(M7): audit event.
     */
    public function shred(string $scope): void
    {
        DataKey::query()
            ->where('scope', $scope)
            ->whereNull('shredded_at')
            ->update(['wrapped_dek' => null, 'shredded_at' => now()]);
    }

    /** @return array{ciphertext: string, wrapped_dek: string|null, key_id: string, key_version: int, scope: string|null} */
    private function encryptWithFreshDek(string $plaintext): array
    {
        $generated = $this->keys->generateDataKey();
        $ciphertext = $this->seal($plaintext, $generated['plaintext']);

        return [
            'ciphertext' => $ciphertext,
            'wrapped_dek' => $generated['wrapped']['ciphertext'],
            'key_id' => $generated['wrapped']['key_id'],
            'key_version' => $generated['wrapped']['key_version'],
            'scope' => null,
        ];
    }

    /** Cifra con AEAD; azzera la DEK in ogni caso (anche su eccezione). */
    private function seal(string $plaintext, string $dek): string
    {
        try {
            $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

            return base64_encode($nonce.sodium_crypto_secretbox($plaintext, $nonce, $dek));
        } finally {
            sodium_memzero($dek);
        }
    }

    /**
     * DEK dello scope (get-or-create) — da chiamare DENTRO una transazione: il lockForUpdate
     * è tenuto fino al commit del chiamante (così copre anche la cifratura successiva).
     *
     * @return array{0: string, 1: string, 2: int} [dek, key_id, key_version]
     */
    private function lockedScopedDek(string $scope): array
    {
        $row = DataKey::query()->where('scope', $scope)->lockForUpdate()->first();

        if ($row !== null && $row->shredded_at !== null) {
            throw new \RuntimeException("Scope {$scope} è stato crypto-shredded: impossibile cifrare nuovi dati.");
        }
        if ($row !== null) {
            return [$this->unwrapRow($row), $row->key_id, $row->key_version];
        }

        $generated = $this->keys->generateDataKey();
        try {
            DataKey::query()->create([
                'scope' => $scope,
                'wrapped_dek' => $generated['wrapped']['ciphertext'],
                'key_id' => $generated['wrapped']['key_id'],
                'key_version' => $generated['wrapped']['key_version'],
            ]);

            return [$generated['plaintext'], $generated['wrapped']['key_id'], $generated['wrapped']['key_version']];
        } catch (UniqueConstraintViolationException) {
            sodium_memzero($generated['plaintext']);
            $row = DataKey::query()->where('scope', $scope)->lockForUpdate()->firstOrFail();

            return [$this->unwrapRow($row), $row->key_id, $row->key_version];
        }
    }

    private function scopedDekForDecrypt(string $scope): string
    {
        $row = DataKey::query()->where('scope', $scope)->first();

        if ($row === null || $row->shredded_at !== null || $row->wrapped_dek === null) {
            throw new \RuntimeException("Scope {$scope}: DEK assente o crypto-shredded → dato irrecuperabile.");
        }

        return $this->unwrapRow($row);
    }

    private function unwrapRow(DataKey $row): string
    {
        return $this->keys->unwrapDataKey([
            'ciphertext' => (string) $row->wrapped_dek,
            'key_id' => $row->key_id,
            'key_version' => $row->key_version,
        ]);
    }
}
