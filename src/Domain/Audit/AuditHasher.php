<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Audit;

/**
 * Calcolo dell'hash di un evento di audit (doc 12 §2.1):
 *   hash(N) = HMAC-SHA-256( canonical_json(evt_N) || prev_hash(N), key )
 *
 * IAM-12: la MAC è KEYED (HMAC) con un segreto che vive FUORI dalle tabelle di audit
 * (`iam.audit.chain_key`, con fallback su APP_KEY). Un attaccante con sola-write sul DB di audit non
 * può quindi ricalcolare la catena dopo una manomissione — cosa possibile con un SHA-256 non-keyed.
 * (Il checkpoint firmato ES256 — vedi AuditChainVerifier IAM-07 — resta l'ancora più forte; questa è
 * difesa in profondità tra un checkpoint e il successivo.)
 *
 * `canonical_json` è deterministico (chiavi ordinate ricorsivamente, niente spazi, UTF-8) così
 * l'hash è riproducibile in fase di verifica indipendentemente dall'ordine di serializzazione.
 */
final class AuditHasher
{
    public const GENESIS = '0000000000000000000000000000000000000000000000000000000000000000';

    /**
     * @param  array<string, mixed>  $payload
     */
    public function hash(array $payload, string $prevHash): string
    {
        return hash_hmac('sha256', $this->canonicalJson($payload).$prevHash, $this->key());
    }

    /**
     * Chiave HMAC della catena. Preferisce `iam.audit.chain_key` (dedicata, ruotabile con re-hash),
     * altrimenti APP_KEY: entrambe vivono fuori dalle tabelle di audit, quindi mantengono la proprietà
     * anti-ricostruzione. In produzione configurare una chiave dedicata e custodirla in un KMS/secret store.
     */
    private function key(): string
    {
        $key = config('iam.audit.chain_key');
        if (is_string($key) && $key !== '') {
            return $key;
        }
        $appKey = config('app.key');

        return is_string($appKey) && $appKey !== '' ? $appKey : 'iam-audit-chain';
    }

    /**
     * @param  array<string, mixed>  $payload
     */
    public function canonicalJson(array $payload): string
    {
        $this->ksortRecursive($payload);

        return json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    }

    /**
     * @param  array<array-key, mixed>  $value
     */
    private function ksortRecursive(array &$value): void
    {
        foreach ($value as &$child) {
            if (is_array($child)) {
                $this->ksortRecursive($child);
            }
        }
        unset($child);

        // Ordina solo le mappe (chiavi stringa); le liste mantengono l'ordine posizionale.
        if ($value !== [] && array_keys($value) !== range(0, count($value) - 1)) {
            ksort($value);
        }
    }
}
