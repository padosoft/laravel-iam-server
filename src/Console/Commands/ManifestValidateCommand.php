<?php

declare(strict_types=1);

namespace Padosoft\Iam\Console\Commands;

use Padosoft\Iam\Domain\Applications\Manifest\ManifestValidator;

/**
 * iam:manifest:validate — valida un manifest senza persistere nulla (doc 01 §10).
 */
final class ManifestValidateCommand extends ManifestCommand
{
    protected $signature = 'iam:manifest:validate {file : path al manifest JSON}';

    protected $description = 'Valida un manifest (schema, slug, referenze) senza applicarlo.';

    public function handle(ManifestValidator $validator): int
    {
        $payload = $this->loadManifest();
        if ($payload === null) {
            return self::FAILURE;
        }

        $result = $validator->validate($payload);
        if ($result->valid) {
            $this->info('Manifest valido.');

            return self::SUCCESS;
        }

        $this->error('Manifest non valido:');
        foreach ($result->errors as $error) {
            $this->line('  - '.$error);
        }

        return self::FAILURE;
    }
}
