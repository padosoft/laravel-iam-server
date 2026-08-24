<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Audit\Outbox;

use Illuminate\Support\Facades\DB;
use Padosoft\Iam\Domain\Audit\AuditChainAppender;
use Padosoft\Iam\Domain\Audit\Models\AuditEvent;
use Padosoft\Iam\Domain\Audit\Webhooks\AuditEventPusher;

/**
 * Worker dell'outbox (doc 12 §5): poll dei messaggi pending, sigillatura nella hash-chain e
 * marcatura delivered. Idempotente: ogni messaggio è lockato e ri-controllato dentro la transazione
 * (un secondo worker o una seconda passata non ri-sigilla → niente eventi di audit duplicati).
 */
final class OutboxProcessor
{
    public function __construct(
        private readonly AuditChainAppender $appender,
        // Opzionale (P2): il push webhook parte DOPO il commit della transazione di sigillatura,
        // mai dentro (niente HTTP in transazione DB) — vedi AuditEventPusher per il gating.
        private readonly ?AuditEventPusher $pusher = null,
    ) {}

    /** Processa fino a $batch messaggi pending. Ritorna il numero di messaggi consegnati. */
    public function process(int $batch = 100): int
    {
        $ids = OutboxMessage::query()
            ->where('status', 'pending')
            ->orderBy('created_at')
            ->orderBy('id')
            ->limit($batch)
            ->pluck('id');

        $delivered = 0;
        foreach ($ids as $id) {
            if (is_string($id) && $this->deliverOne($id)) {
                $delivered++;
            }
        }

        return $delivered;
    }

    private function deliverOne(string $id): bool
    {
        try {
            $event = DB::transaction(function () use ($id): ?AuditEvent {
                $message = OutboxMessage::query()->lockForUpdate()->find($id);
                // Un altro worker può aver già consegnato tra il poll e il lock: ri-controlla sotto lock.
                if ($message === null || $message->status !== 'pending') {
                    return null;
                }

                $event = $this->appender->append($message->payload_json);

                $message->forceFill([
                    'status' => 'delivered',
                    'audit_uuid' => $event->uuid,
                    'attempts' => $message->attempts + 1,
                    'delivered_at' => now(),
                ])->save();

                return $event;
            });

            if ($event === null) {
                return false;
            }

            // Push webhook FUORI dalla transazione: l'evento è già sigillato e il messaggio marcato
            // delivered; una consegna webhook fallita non deve fare rollback della sigillatura.
            $this->pusher?->push($event);

            return true;
        } catch (\Throwable $e) {
            // Poison message: senza registrare il fallimento, la tx fa rollback e il messaggio
            // rientrerebbe in OGNI poll all'infinito. Incrementiamo attempts in una tx separata e,
            // oltre la soglia, lo marchiamo 'failed' (→ DLQ, fuori dal polling).
            $this->recordFailure($id, $e);

            return false;
        }
    }

    private function recordFailure(string $id, \Throwable $e): void
    {
        DB::transaction(function () use ($id, $e): void {
            $message = OutboxMessage::query()->lockForUpdate()->find($id);
            if ($message === null || $message->status !== 'pending') {
                return;
            }

            $attempts = $message->attempts + 1;
            $message->forceFill([
                'attempts' => $attempts,
                'status' => $attempts >= $this->maxAttempts() ? 'failed' : 'pending',
                'last_error' => mb_substr($e->getMessage(), 0, 1000),
            ])->save();
        });
    }

    private function maxAttempts(): int
    {
        $max = config('iam.audit.outbox_max_attempts', 5);

        return is_int($max) && $max > 0 ? $max : 5;
    }
}
