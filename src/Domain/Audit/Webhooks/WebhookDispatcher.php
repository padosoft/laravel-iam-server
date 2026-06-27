<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Audit\Webhooks;

use Padosoft\Iam\Domain\Audit\Models\AuditEvent;
use Padosoft\Iam\Domain\Audit\Webhooks\Models\WebhookDelivery;
use Padosoft\Iam\Domain\Audit\Webhooks\Models\WebhookSubscription;

/**
 * Recapita un evento sigillato alle subscription webhook che lo matchano (doc 12 §6). Crea una
 * delivery idempotente per (subscription, event_uuid) e ne tenta la consegna; gli errori non
 * fanno fallire le altre subscription.
 */
final class WebhookDispatcher
{
    public function __construct(private readonly WebhookSender $sender) {}

    public function dispatch(AuditEvent $event): void
    {
        // Tenant isolation: un evento di un'org va SOLO alle subscription di quell'org; un evento
        // globale (org null, es. il meta-evento subject.erased) va SOLO alle subscription globali —
        // mai a tutte, altrimenti si fa leak cross-tenant dei dati di audit.
        $subscriptions = WebhookSubscription::query()
            ->where('status', 'active')
            ->when(
                $event->organization_id !== null,
                fn ($q) => $q->where('organization_id', $event->organization_id),
                fn ($q) => $q->whereNull('organization_id'),
            )
            ->get();

        foreach ($subscriptions as $subscription) {
            if (!$this->matches($subscription->event_filters, $event->event_type)) {
                continue;
            }

            // Idempotenza: una sola delivery per (subscription, evento). Il claim atomico dentro
            // send() evita il doppio invio sotto concorrenza (e salta delivered/failed).
            $delivery = WebhookDelivery::query()->firstOrCreate([
                'subscription_id' => $subscription->id,
                'event_uuid' => $event->uuid,
            ]);

            $this->sender->send($subscription, $delivery, $event);
        }
    }

    /**
     * @param  list<string>  $filters
     */
    private function matches(array $filters, string $eventType): bool
    {
        foreach ($filters as $filter) {
            if ($filter === '*' || $filter === $eventType) {
                return true;
            }
            // Pattern a prefisso "grant.*": matcha tutto ciò che inizia con "grant.".
            if (str_ends_with($filter, '*') && str_starts_with($eventType, substr($filter, 0, -1))) {
                return true;
            }
        }

        return false;
    }
}
