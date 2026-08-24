<?php

declare(strict_types=1);

namespace Padosoft\Iam\Http\Admin\Controllers;

use Illuminate\Http\JsonResponse;
use Padosoft\Iam\Http\Admin\AdminController;

/**
 * Admin API — Capabilities (P4). Un solo GET read-only che dichiara quali moduli opzionali e
 * feature questo server ha attivi, così il pannello (laravel-iam-console) mostra/nasconde pagine e
 * nav SENZA sondare i singoli endpoint a colpi di 409 (pattern DirectorySourcesController).
 *
 * Contratto per i moduli: ogni modulo opzionale si dichiara a boot scrivendo la PROPRIA chiave in
 * config — `config()->set('iam.capabilities.modules.<nome>', true)` (ed eventuali feature flags in
 * `iam.capabilities.features.<nome>.*`). Il core contribuisce le chiavi che possiede già
 * (`directory` da iam.directory.enabled). Un modulo assente semplicemente non compare → il client
 * tratta le chiavi mancanti come false.
 *
 * Autenticato ma SENZA `iam.can`: il pannello ne ha bisogno al bootstrap per QUALSIASI operatore
 * (anche a permessi minimi, per decidere cosa mostrare), e il payload non è un dato tenant — dice
 * solo quali pacchetti sono installati, cosa che gli endpoint gated rivelano comunque via 409/404.
 */
final class CapabilitiesController extends AdminController
{
    public function index(): JsonResponse
    {
        /** @var array<string, mixed> $modules */
        $modules = (array) config('iam.capabilities.modules', []);
        /** @var array<string, mixed> $features */
        $features = (array) config('iam.capabilities.features', []);

        return $this->ok([
            'modules' => array_map(
                static fn (mixed $enabled): bool => (bool) $enabled,
                // Le chiavi possedute dal core prima, così un modulo non può sovrascriverle.
                array_replace($modules, ['directory' => config('iam.directory.enabled', false) === true]),
            ),
            'features' => $features,
        ]);
    }
}
