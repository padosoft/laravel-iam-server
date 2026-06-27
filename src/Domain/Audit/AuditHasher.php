<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Audit;

/**
 * Calcolo dell'hash di un evento di audit (doc 12 §2.1):
 *   hash(N) = SHA-256( canonical_json(evt_N) || prev_hash(N) )
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
        return hash('sha256', $this->canonicalJson($payload).$prevHash);
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
