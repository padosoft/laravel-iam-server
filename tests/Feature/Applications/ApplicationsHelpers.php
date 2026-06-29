<?php

declare(strict_types=1);

use Padosoft\Iam\Domain\Applications\Manifest\ManifestApplier;
use Padosoft\Iam\Domain\Applications\Manifest\ManifestRegistry;
use Padosoft\Iam\Domain\Applications\Models\Application;
use Padosoft\Iam\Domain\Applications\Models\Manifest;

// Helper condivisi dai test Applications (Validation/Diff/Apply/Lifecycle). Centralizzati qui e
// inclusi una sola volta da tests/Pest.php: se vivono dentro un singolo file di test, l'ordine di
// inclusione dei file non è garantito e la suite può fallire con un fatal redeclare/undefined.

/** @return array<string, mixed> */
function validManifest(): array
{
    return [
        'schema' => 'laravel-iam.manifest.v2',
        'app' => ['key' => 'warehouse', 'name' => 'Warehouse Management', 'type' => 'laravel', 'risk_level' => 'high'],
        'auth' => [
            'client_type' => 'confidential',
            'redirect_uris' => ['https://warehouse.test/iam/callback'],
        ],
        'permissions' => [
            ['key' => 'stock.read', 'resource' => 'stock', 'action' => 'read', 'risk' => 'low'],
            ['key' => 'stock.adjust', 'resource' => 'stock', 'action' => 'adjust', 'risk' => 'high', 'requires_step_up' => true],
        ],
        'roles' => [
            ['key' => 'stock_operator', 'label' => 'Stock Operator', 'permissions' => ['stock.read', 'stock.adjust']],
        ],
    ];
}

function manifests(): ManifestRegistry
{
    return app(ManifestRegistry::class);
}

/** Submit → approva (gate umano simulato) → apply. */
function submitApproveApply(array $payload): Application
{
    $manifest = app(ManifestRegistry::class)->submit($payload);
    $manifest->forceFill(['status' => 'approved'])->save();

    return app(ManifestApplier::class)->apply($manifest);
}

/** @return array<string, mixed> */
function lowRiskManifest(): array
{
    return [
        'schema' => 'laravel-iam.manifest.v2',
        'app' => ['key' => 'reports', 'name' => 'Reports', 'risk_level' => 'low'],
        'auth' => ['client_type' => 'confidential', 'redirect_uris' => ['https://reports.test/cb']],
        'permissions' => [['key' => 'report.read', 'risk' => 'low']],
        'roles' => [['key' => 'viewer', 'permissions' => ['report.read']]],
    ];
}

/** Simula lo stato applicato: crea l'Application e ne fissa il current_manifest_id (apply = M6.3). */
function setApplied(array $payload): Manifest
{
    $manifest = app(ManifestRegistry::class)->submit($payload);
    $app = Application::query()->firstOrCreate(['key' => $payload['app']['key']], ['name' => $payload['app']['name']]);
    $app->forceFill(['current_manifest_id' => $manifest->id])->save();

    return $manifest;
}
