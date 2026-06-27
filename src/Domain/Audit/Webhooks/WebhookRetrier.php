<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Audit\Webhooks;

use Padosoft\Iam\Domain\Audit\Models\AuditEvent;
use Padosoft\Iam\Domain\Audit\Webhooks\Models\WebhookDelivery;
use Padosoft\Iam\Domain\Audit\Webhooks\Models\WebhookSubscription;

/**
 * Riconsegna le delivery webhook scadute (doc 12 §6): status 'retrying' con next_retry_at passato.
 * Ogni tentativo aggiorna il log; oltre la soglia il WebhookSender la marca 'failed' (DLQ).
 */
final class WebhookRetrier
{
    public function __construct(private readonly WebhookSender $sender) {}

    public function retryDue(int $batch = 100): int
    {
        // Recupero delle delivery orfane: un processo morto DOPO il claim (kill -9/OOM) lascia la
        // riga in 'sending', che send() non ri-claima. Oltre un timeout la riportiamo a 'retrying'.
        $timeout = config('iam.audit.webhook_sending_timeout', 300);
        $timeout = is_int($timeout) && $timeout > 0 ? $timeout : 300;
        WebhookDelivery::query()
            ->where('status', 'sending')
            ->where('updated_at', '<', now()->subSeconds($timeout))
            ->update(['status' => 'retrying', 'next_retry_at' => now()]);

        $due = WebhookDelivery::query()
            ->where('status', 'retrying')
            ->whereNotNull('next_retry_at')
            ->where('next_retry_at', '<=', now())
            ->orderBy('next_retry_at')
            ->limit($batch)
            ->get();

        $retried = 0;
        foreach ($due as $delivery) {
            $subscription = WebhookSubscription::query()->find($delivery->subscription_id);
            $event = AuditEvent::query()->find($delivery->event_uuid);
            if ($subscription === null || $event === null) {
                continue;
            }

            $this->sender->send($subscription, $delivery, $event);
            $retried++;
        }

        return $retried;
    }
}
