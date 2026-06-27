<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Audit\Export;

use Padosoft\Iam\Domain\Audit\Models\AuditEvent;

/**
 * Formatta un evento di audit come riga LEEF 2.0 (doc 12 §4) per QRadar e SIEM compatibili:
 *   LEEF:2.0|Vendor|Product|Version|EventID|key=value<tab>key=value...
 */
final class LeefFormatter
{
    public function format(AuditEvent $event): string
    {
        // LEEF 2.0 richiede 6 campi header: l'ultimo dichiara il carattere delimitatore degli
        // attributi (x09 = tab), altrimenti un parser strict interpreta male il primo attributo.
        $header = implode('|', [
            'LEEF:2.0',
            'Padosoft',
            'Laravel IAM',
            '1.0',
            $this->escapeHeader($event->event_type),
            'x09',
        ]);

        $attributes = $this->attributes([
            'cat' => $event->event_type,
            // devTime in ISO-8601 + devTimeFormat esplicito: evita che QRadar interpreti l'epoch-ms
            // come epoch-s (timestamp sballato).
            'devTime' => $event->occurred_at->utc()->format('Y-m-d\TH:i:s.v\Z'),
            'devTimeFormat' => "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'",
            'usrName' => $event->actor_user_id,
            'targetType' => $event->target_type,
            'targetId' => $event->target_id,
            'sev' => $event->risk_level,
            'iamHash' => $event->hash,
            'iamStream' => $event->stream,
        ]);

        return $header.'|'.$attributes;
    }

    /** @param array<string, string|null> $pairs */
    private function attributes(array $pairs): string
    {
        $parts = [];
        foreach ($pairs as $key => $value) {
            if ($value !== null && $value !== '') {
                $parts[] = $key.'='.$this->escapeValue($value);
            }
        }

        // Delimitatore di default LEEF 2.0 = tab (dichiarato nel 6° campo header).
        return implode("\t", $parts);
    }

    /** Header LEEF: pipe e backslash escapati; CR/LF/tab rimossi (non possono stare nell'header). */
    private function escapeHeader(string $value): string
    {
        $value = str_replace(["\r", "\n", "\t"], ['', '', ' '], $value);

        return str_replace(['\\', '|'], ['\\\\', '\\|'], $value);
    }

    /** Valori LEEF: `=` rompe lo split chiave=valore; tab è il delimitatore; CR/LF iniettano righe. */
    private function escapeValue(string $value): string
    {
        return str_replace(['\\', '=', "\t", "\r", "\n"], ['\\\\', '\\=', ' ', ' ', ' '], $value);
    }
}
