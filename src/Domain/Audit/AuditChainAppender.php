<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Audit;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Padosoft\Iam\Domain\Audit\Models\AuditEvent;
use Padosoft\Iam\Domain\Audit\Models\AuditHead;

/**
 * Sigilla un evento nella hash-chain del suo stream (doc 12 §2.3). Tutto in transazione con
 * `lockForUpdate` sulla testa dello stream: il seq e il prev_hash sono assegnati in modo
 * serializzato, così due eventi concorrenti producono una catena coerente (nessun fork).
 */
final class AuditChainAppender
{
    public function __construct(private readonly AuditHasher $hasher) {}

    /**
     * @param  array<string, mixed>  $attributes  campi descrittivi dell'evento (almeno `stream` e `event_type`)
     */
    public function append(array $attributes): AuditEvent
    {
        $stream = $attributes['stream'] ?? null;
        if (!is_string($stream) || $stream === '') {
            throw new \InvalidArgumentException('Un evento di audit richiede uno "stream" non vuoto.');
        }

        // Garantiamo la riga genesi PRIMA della transazione: con un firstOrCreate dentro la
        // transazione, due prime scritture concorrenti sullo stesso stream prendono gap-lock InnoDB
        // in conflitto → deadlock (non ritentato). insertOrIgnore è idempotente e non lockante.
        AuditHead::query()->insertOrIgnore(['stream' => $stream, 'seq' => 0, 'hash' => null]);

        return DB::transaction(function () use ($attributes, $stream): AuditEvent {
            $head = AuditHead::query()->lockForUpdate()->find($stream)
                ?? throw new \RuntimeException("Testa della catena assente per lo stream \"{$stream}\".");

            $prevHash = is_string($head->hash) && $head->hash !== '' ? $head->hash : AuditHasher::GENESIS;
            $seq = $head->seq + 1;

            $event = new AuditEvent;
            $event->fill($attributes);
            // L'uuid deve esistere PRIMA dell'hash (entra nel payload canonico): lo assegniamo qui
            // invece di lasciarlo all'evento `creating` di HasUlids.
            $event->uuid = (string) Str::ulid();
            $event->occurred_at = $event->occurred_at ?? now();
            $event->seq = $seq;
            $event->prev_hash = $prevHash;
            $event->hash = $this->hasher->hash($event->canonicalPayload(), $prevHash);
            $event->sealed_at = now();
            $event->save();

            $head->forceFill(['hash' => $event->hash, 'seq' => $seq, 'sealed_at' => now()])->save();

            return $event;
        });
    }
}
