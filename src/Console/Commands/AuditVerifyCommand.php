<?php

declare(strict_types=1);

namespace Padosoft\Iam\Console\Commands;

use Illuminate\Console\Command;
use Padosoft\Iam\Domain\Audit\AuditChainVerifier;

/**
 * iam:audit:verify — ricalcola la hash-chain di uno stream e segnala il primo punto di rottura
 * (doc 12 §2.4). Da usare in CI, audit periodico o durante un incident.
 */
final class AuditVerifyCommand extends Command
{
    protected $signature = 'iam:audit:verify {--stream=global : stream da verificare (es. organization_id o "global")}';

    protected $description = 'Verifica l\'integrità tamper-evident della hash-chain di audit di uno stream.';

    public function handle(AuditChainVerifier $verifier): int
    {
        $stream = $this->option('stream');
        if (!is_string($stream) || $stream === '') {
            $this->error('Opzione --stream mancante.');

            return self::FAILURE;
        }

        $result = $verifier->verify($stream);

        if ($result->valid) {
            $this->info("OK — catena integra per lo stream \"{$stream}\" ({$result->checked} eventi verificati).");

            return self::SUCCESS;
        }

        $this->error("ROTTURA RILEVATA nello stream \"{$stream}\" dopo {$result->checked} eventi.");
        $this->line('  Primo evento compromesso: '.($result->firstBrokenUuid ?? 'n/a (rottura strutturale: coda/testa)'));
        $this->line("  Motivo: {$result->reason}");

        return self::FAILURE;
    }
}
