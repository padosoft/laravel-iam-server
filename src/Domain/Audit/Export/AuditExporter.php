<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Audit\Export;

use Padosoft\Iam\Domain\Audit\Models\AuditEvent;

/**
 * Esporta gli eventi di audit sigillati verso SIEM/ELK (doc 12 §4), in batch. Modalità streaming
 * (push near-real-time via outbox) → milestone successiva/deploy. Yielda lazy (cursor) per non
 * caricare in memoria interi stream.
 *
 * @phpstan-type OcsfEvent array<string, mixed>
 */
final class AuditExporter
{
    public function __construct(
        private readonly OcsfMapper $ocsf,
        private readonly CefFormatter $cef,
        private readonly LeefFormatter $leef,
    ) {}

    /**
     * @return iterable<array<string, mixed>|string> OCSF → array; CEF/LEEF → stringa
     */
    public function export(string $stream, ?string $from = null, ?string $to = null, string $format = 'ocsf'): iterable
    {
        $query = AuditEvent::query()->where('stream', $stream)->orderBy('seq');
        if ($from !== null) {
            $query->where('occurred_at', '>=', $from);
        }
        if ($to !== null) {
            $query->where('occurred_at', '<=', $to);
        }

        foreach ($query->cursor() as $event) {
            yield $this->formatOne($event, $format);
        }
    }

    /**
     * @return array<string, mixed>|string
     */
    private function formatOne(AuditEvent $event, string $format): array|string
    {
        return match (strtolower($format)) {
            'cef' => $this->cef->format($event),
            'leef' => $this->leef->format($event),
            'ocsf' => $this->ocsf->map($event),
            default => throw new \InvalidArgumentException("Formato di export non supportato: {$format} (ocsf|cef|leef)."),
        };
    }
}
