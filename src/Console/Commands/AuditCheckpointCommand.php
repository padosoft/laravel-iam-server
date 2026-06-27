<?php

declare(strict_types=1);

namespace Padosoft\Iam\Console\Commands;

use Illuminate\Console\Command;
use Padosoft\Iam\Domain\Audit\AuditCheckpointer;

/**
 * iam:audit:checkpoint — firma la testa corrente della hash-chain di uno stream (doc 12 §2.2).
 * Da schedulare (es. ogni ora / ogni N eventi) per ancorare periodicamente la catena.
 */
final class AuditCheckpointCommand extends Command
{
    protected $signature = 'iam:audit:checkpoint {--stream=global : stream da sigillare}';

    protected $description = 'Crea un checkpoint firmato della hash-chain di audit di uno stream.';

    public function handle(AuditCheckpointer $checkpointer): int
    {
        $stream = $this->option('stream');
        if (!is_string($stream) || $stream === '') {
            $this->error('Opzione --stream mancante.');

            return self::FAILURE;
        }

        $checkpoint = $checkpointer->checkpoint($stream);
        if ($checkpoint === null) {
            $this->warn("Nessun evento da sigillare per lo stream \"{$stream}\".");

            return self::FAILURE;
        }

        $this->info("Checkpoint creato per \"{$stream}\" fino a seq {$checkpoint->up_to_seq} (head {$checkpoint->head_hash}).");

        return self::SUCCESS;
    }
}
