<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Audit\Export;

use Padosoft\Iam\Domain\Audit\Models\AuditEvent;

/**
 * Formatta un evento di audit come riga CEF (doc 12 §4) per SIEM legacy (ArcSight, ecc.):
 *   CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extension
 * Header e extension hanno regole di escaping diverse (vedi {@see escapeHeader}/{@see escapeValue}).
 */
final class CefFormatter
{
    /** risk_level → severità CEF 0..10. */
    private const SEVERITY = ['low' => 3, 'medium' => 5, 'high' => 7, 'critical' => 9];

    public function format(AuditEvent $event): string
    {
        $header = implode('|', [
            'CEF:0',
            'Padosoft',
            'Laravel IAM',
            '1.0',
            $this->escapeHeader($event->event_type),
            $this->escapeHeader($event->event_type),
            (string) (self::SEVERITY[$event->risk_level] ?? 0),
        ]);

        $extensions = $this->extensions([
            'rt' => (string) $event->occurred_at->getTimestampMs(),
            // L'attore è la SORGENTE dell'azione → suser/suid (non duser/duid, che è il target).
            'suid' => $event->actor_user_id,
            'suser' => $event->actor_user_id,
            'cs1Label' => 'targetType',
            'cs1' => $event->target_type,
            'cs2Label' => 'targetId',
            'cs2' => $event->target_id,
            'cs3Label' => 'iamHash',
            'cs3' => $event->hash,
            'dvchost' => $event->stream,
        ]);

        return $header.'|'.$extensions;
    }

    /** @param array<string, string|null> $pairs */
    private function extensions(array $pairs): string
    {
        $parts = [];
        foreach ($pairs as $key => $value) {
            if ($value !== null && $value !== '') {
                $parts[] = $key.'='.$this->escapeValue($value);
            }
        }

        return implode(' ', $parts);
    }

    /** Header CEF: si escapano backslash e pipe; CR/LF rimossi (un header non può contenerli → anti log-injection). */
    private function escapeHeader(string $value): string
    {
        $value = str_replace(["\r", "\n"], ['', ''], $value);

        return str_replace(['\\', '|'], ['\\\\', '\\|'], $value);
    }

    /** Extension CEF: si escapano backslash, uguale e CR/LF (anti log-injection nel SIEM). */
    private function escapeValue(string $value): string
    {
        return str_replace(['\\', '=', "\r", "\n"], ['\\\\', '\\=', '\\r', '\\n'], $value);
    }
}
