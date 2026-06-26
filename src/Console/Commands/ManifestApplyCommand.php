<?php

declare(strict_types=1);

namespace Padosoft\Iam\Console\Commands;

use Padosoft\Iam\Domain\Applications\Manifest\ManifestApplier;
use Padosoft\Iam\Domain\Applications\Manifest\ManifestRegistry;

/**
 * iam:manifest:apply — sottomette e applica un manifest (doc 01 §10). I cambi sensibili
 * richiedono --approve (gate umano). Mostra una sola volta il secret di un nuovo client confidential.
 */
final class ManifestApplyCommand extends ManifestCommand
{
    protected $signature = 'iam:manifest:apply {file : path al manifest JSON} {--approve : approva i cambi che richiedono gate} {--by= : attore}';

    protected $description = 'Sottomette e applica un manifest applicazione.';

    public function handle(ManifestRegistry $registry, ManifestApplier $applier): int
    {
        $payload = $this->loadManifest();
        if ($payload === null) {
            return self::FAILURE;
        }
        $by = $this->byOption();

        $manifest = $registry->submit($payload, $by);
        if ($manifest->status === 'rejected') {
            $this->error('Manifest non valido:');
            foreach ($manifest->validation_errors ?? [] as $error) {
                $this->line('  - '.$error);
            }

            return self::FAILURE;
        }

        if ($manifest->status === 'pending_approval') {
            if ($this->option('approve') !== true) {
                $this->warn('Il manifest richiede approval (cambi sensibili). Rilancia con --approve o approva dal pannello.');

                return self::INVALID;
            }
            $registry->approve($manifest, $by);
        }

        $application = $applier->apply($manifest);
        $this->info("Manifest v{$manifest->version} applicato a \"{$application->key}\".");

        $secret = $applier->generatedSecret();
        if ($secret !== null) {
            $this->warn('Client secret (mostrato UNA sola volta, archivialo in sicurezza):');
            $this->line('  cli_'.$application->key.' : '.$secret);
        }

        return self::SUCCESS;
    }

    private function byOption(): ?string
    {
        $by = $this->option('by');

        return is_string($by) && $by !== '' ? $by : null;
    }
}
