<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Audit\Export;

use Padosoft\Iam\Domain\Audit\Models\AuditEvent;

/**
 * Normalizza un evento di audit nello schema OCSF (doc 12 §4, ADR-12.2). OCSF è lo standard
 * cross-vendor (Splunk/Datadog/Sentinel/Elastic) → evita un formato proprietario. `unmapped`
 * trasporta i campi IAM-specifici (incluso l'hash della catena = anchoring esterno gratuito).
 */
final class OcsfMapper
{
    /** risk_level IAM → severity_id OCSF (1 Informational … 5 Critical). */
    private const SEVERITY = ['low' => 2, 'medium' => 3, 'high' => 4, 'critical' => 5];

    /**
     * @return array<string, mixed>
     */
    public function map(AuditEvent $event): array
    {
        return [
            'class_uid' => 3005,        // Account Change / Entitlement
            'category_uid' => 3,        // Identity & Access Management
            'time' => $event->occurred_at->getTimestampMs(),
            'severity_id' => self::SEVERITY[$event->risk_level] ?? 1,
            'actor' => [
                'user' => ['uid' => $event->actor_user_id],
                'app' => ['uid' => $event->actor_client_id],
            ],
            'entity' => [
                'type' => $event->target_type,
                'uid' => $event->target_id,
            ],
            'metadata' => [
                'product' => ['name' => 'Laravel IAM', 'vendor_name' => 'Padosoft'],
                'correlation_uid' => $event->correlation_id,
                'log_provider' => 'iam-audit',
            ],
            'unmapped' => [
                'iam_event_type' => $event->event_type,
                'iam_stream' => $event->stream,
                'iam_seq' => $event->seq,
                'iam_hash' => $event->hash,
                'iam_organization_id' => $event->organization_id,
            ],
        ];
    }
}
