<?php

declare(strict_types=1);

namespace Padosoft\Iam\Console\Commands;

use Illuminate\Console\Command;
use Padosoft\Iam\Domain\Applications\Manifest\ManifestRegistry;

/**
 * iam:manifest:rollback — ri-applica la precedente versione applicata di un'app (doc 01 §10.1).
 */
final class ManifestRollbackCommand extends Command
{
    protected $signature = 'iam:manifest:rollback {app : key dell\'applicazione}';

    protected $description = 'Effettua il rollback alla precedente versione di manifest applicata.';

    public function handle(ManifestRegistry $registry): int
    {
        $appKey = $this->argument('app');
        if (!is_string($appKey) || $appKey === '') {
            $this->error('App key mancante.');

            return self::FAILURE;
        }

        $application = $registry->rollback($appKey);
        if ($application === null) {
            $this->error("Nessuna versione precedente applicata per \"{$appKey}\".");

            return self::FAILURE;
        }

        $this->info("Rollback eseguito per \"{$appKey}\" (manifest v{$application->current_manifest_id}).");

        return self::SUCCESS;
    }
}
