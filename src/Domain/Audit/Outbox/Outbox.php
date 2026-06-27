<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Audit\Outbox;

/**
 * Scrittura nell'outbox transazionale (doc 12 §5). Da chiamare NELLA stessa transazione della
 * mutazione di dominio: se il commit riesce, l'evento esiste di sicuro (at-least-once). La
 * sigillatura nella hash-chain e la consegna avvengono dopo, via {@see OutboxProcessor}.
 */
final class Outbox
{
    /**
     * @param  array<string, mixed>  $auditAttributes  attributi dell'evento di audit (almeno `stream` e `event_type`)
     */
    public function publish(array $auditAttributes): OutboxMessage
    {
        $stream = $auditAttributes['stream'] ?? null;
        $eventType = $auditAttributes['event_type'] ?? null;
        if (!is_string($stream) || $stream === '' || !is_string($eventType) || $eventType === '') {
            throw new \InvalidArgumentException('Un messaggio outbox richiede "stream" ed "event_type" non vuoti.');
        }

        $message = new OutboxMessage;
        $message->fill([
            'event_type' => $eventType,
            'stream' => $stream,
            'payload_json' => $auditAttributes,
            'created_at' => now(),
        ]);
        $message->save();

        return $message;
    }
}
