<?php

declare(strict_types=1);

namespace Padosoft\Iam\Console\Commands;

use Illuminate\Console\Command;

/**
 * Base dei comandi manifest: carica e parsa il file JSON del manifest (doc 01 §10).
 */
abstract class ManifestCommand extends Command
{
    /**
     * @return array<string, mixed>|null
     */
    protected function loadManifest(): ?array
    {
        $file = $this->argument('file');
        if (!is_string($file) || !is_file($file)) {
            $this->error('File manifest non trovato: '.(is_string($file) ? $file : 'n/d'));

            return null;
        }
        $content = file_get_contents($file);
        if ($content === false) {
            $this->error('Impossibile leggere il file manifest.');

            return null;
        }
        try {
            $data = json_decode($content, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            $this->error('Manifest JSON non valido.');

            return null;
        }
        if (!is_array($data)) {
            return null;
        }

        // Il manifest è un oggetto JSON (chiavi stringa): normalizza per il tipo.
        $out = [];
        foreach ($data as $key => $value) {
            $out[(string) $key] = $value;
        }

        return $out;
    }
}
