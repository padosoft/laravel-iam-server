<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Governance;

use Padosoft\Iam\Domain\Authorization\Models\Grant;

/**
 * Cattura dell'uso dei grant (doc 14 §2/§7): il PDP segnala, ad ogni decisione `allow`, il grant
 * che ha prodotto il permit; qui si bufferizza e si scrive `last_used_at` in BATCH (un solo UPDATE),
 * per non aggiungere una scrittura sincrona alla latenza di ogni autorizzazione. È il segnale che
 * alimenta Access Review (accessi mai/poco usati) e il recommender di least-privilege.
 *
 * Singleton di richiesta: il flush avviene a fine richiesta (app()->terminating) o esplicitamente.
 */
final class GrantUsageRecorder
{
    /** @var array<string, true> set di grant id usati (dedup) */
    private array $buffer = [];

    public function record(string $grantId): void
    {
        if ($grantId !== '') {
            $this->buffer[$grantId] = true;
        }
    }

    public function flush(): void
    {
        if ($this->buffer === []) {
            return;
        }

        $ids = array_keys($this->buffer);

        // `last_used_at` non è fillable: scrittura diretta via query builder (codice fidato).
        // Il buffer si svuota SOLO dopo un UPDATE andato a buon fine: se la scrittura lancia
        // (es. DB down a fine richiesta) i grant restano in coda e un flush successivo riprova,
        // invece di perdere silenziosamente il segnale d'uso (Access Review/least-privilege).
        Grant::query()->whereIn('id', $ids)->update(['last_used_at' => now()]);

        $this->buffer = [];
    }
}
