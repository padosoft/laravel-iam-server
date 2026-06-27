<?php

declare(strict_types=1);

namespace Padosoft\Iam\Console\Commands;

use Illuminate\Console\Command;
use Padosoft\Iam\Domain\Audit\Export\AuditExporter;

/**
 * iam:audit:export — esporta gli eventi di audit di uno stream verso stdout nel formato richiesto
 * (OCSF/CEF/LEEF, doc 12 §4). Da reindirizzare a un collector/file o pipeline verso ELK/SIEM.
 */
final class AuditExportCommand extends Command
{
    protected $signature = 'iam:audit:export
        {--stream=global : stream da esportare}
        {--format=ocsf : ocsf|cef|leef}
        {--from= : occorrenza minima (ISO-8601)}
        {--to= : occorrenza massima (ISO-8601)}';

    protected $description = 'Esporta gli eventi di audit di uno stream in OCSF/CEF/LEEF.';

    public function handle(AuditExporter $exporter): int
    {
        $stream = $this->stringOption('stream', 'global');
        $format = $this->stringOption('format', 'ocsf');
        $from = $this->stringOption('from', '');
        $to = $this->stringOption('to', '');

        try {
            foreach ($exporter->export($stream, $from !== '' ? $from : null, $to !== '' ? $to : null, $format) as $row) {
                $this->line(is_array($row) ? json_encode($row, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR) : $row);
            }
        } catch (\InvalidArgumentException $e) {
            $this->error($e->getMessage());

            return self::FAILURE;
        }

        return self::SUCCESS;
    }

    private function stringOption(string $name, string $default): string
    {
        $value = $this->option($name);

        return is_string($value) && $value !== '' ? $value : $default;
    }
}
