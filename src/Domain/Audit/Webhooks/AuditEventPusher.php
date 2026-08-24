<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Audit\Webhooks;

use Padosoft\Iam\Domain\Audit\Models\AuditEvent;

/**
 * Push best-effort di un evento appena sigillato verso le subscription webhook (doc 12 §6) — il
 * call site che mancava tra la hash-chain e il WebhookDispatcher. È il canale con cui revoche di
 * sessione/grant e lo stream `delegation` raggiungono i PEP e gli agent SENZA attendere un poll
 * (freshness della revoca: il token delegato ha TTL breve, il push accorcia anche quella finestra).
 *
 * Regole:
 *  - gated su `iam.audit.webhooks.push_enabled` (default attivo): un host può spegnere il push
 *    senza toccare le subscription;
 *  - MAI far fallire l'operazione sorgente: qualunque Throwable della consegna (tabelle webhook
 *    non migrate, rete, bug del sender) viene report()-ato e assorbito — l'evento è già sigillato
 *    nella catena, che resta la source of truth; i tentativi falliti li riprende iam:webhooks-retry.
 */
final class AuditEventPusher
{
    public function __construct(private readonly WebhookDispatcher $dispatcher) {}

    public function push(AuditEvent $event): void
    {
        if (config('iam.audit.webhooks.push_enabled', true) !== true) {
            return;
        }

        try {
            $this->dispatcher->dispatch($event);
        } catch (\Throwable $e) {
            report($e);
        }
    }
}
