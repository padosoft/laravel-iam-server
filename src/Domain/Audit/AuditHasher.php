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
        $canonical = $this->canonicalJson($payload).$prevHash;
        $key = $this->key();

        // IAM-12: HMAC keyed SOLO se è configurata una chiave DEDICATA (`iam.audit.chain_key`, fuori dalle
        // tabelle di audit). È OPT-IN di proposito: senza chiave resta SHA-256 non-keyed, così un upgrade
        // NON invalida le catene esistenti (nessuna migrazione forzata) e non esiste un fallback a chiave
        // hard-coded (che vanificherebbe la proprietà keyed). Ruotare la chiave richiede un re-hash della
        // catena esistente. La difesa forte contro un tamper con write sul DB resta il checkpoint firmato
        // ES256 (IAM-07), sempre attivo; l'HMAC è difesa in profondità tra un checkpoint e il successivo.
        return $key !== null
            ? hash_hmac('sha256', $canonical, $key)
            : hash('sha256', $canonical);
    }

    private function key(): ?string
    {
        $key = config('iam.audit.chain_key');

        return is_string($key) && $key !== '' ? $key : null;
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
