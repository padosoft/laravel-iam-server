<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Padosoft\Iam\Domain\Applications\Manifest\ManifestRegistry;

uses(RefreshDatabase::class);

// lowRiskManifest() / setApplied() vivono in ApplicationsHelpers.php (incluso da tests/Pest.php).

it('change additivo a basso rischio → approved senza approval', function () {
    setApplied(lowRiskManifest());

    $payload = lowRiskManifest();
    $payload['permissions'][] = ['key' => 'report.export', 'risk' => 'low'];
    $payload['roles'][0]['permissions'][] = 'report.export';

    $manifest = app(ManifestRegistry::class)->submit($payload);

    expect($manifest->status)->toBe('approved')
        ->and($manifest->requires_approval)->toBeFalse()
        ->and($manifest->diff['permissions']['added'])->toContain('report.export');
});

it('rimozione di un permission → breaking + approval', function () {
    setApplied(lowRiskManifest());

    $payload = lowRiskManifest();
    $payload['permissions'] = [];
    $payload['roles'][0]['permissions'] = [];

    $manifest = app(ManifestRegistry::class)->submit($payload);

    expect($manifest->status)->toBe('pending_approval')
        ->and($manifest->diff['breaking'])->toBeTrue()
        ->and($manifest->diff['permissions']['removed'])->toContain('report.read');
});

it('cambio di una redirect_uri → approval obbligatoria', function () {
    setApplied(lowRiskManifest());

    $payload = lowRiskManifest();
    $payload['auth']['redirect_uris'] = ['https://reports.test/new-cb'];

    expect(app(ManifestRegistry::class)->submit($payload)->status)->toBe('pending_approval');
});

it('un nuovo permission high-risk → approval obbligatoria', function () {
    setApplied(lowRiskManifest());

    $payload = lowRiskManifest();
    $payload['permissions'][] = ['key' => 'report.purge', 'risk' => 'critical'];

    $manifest = app(ManifestRegistry::class)->submit($payload);
    expect($manifest->status)->toBe('pending_approval')->and($manifest->requires_approval)->toBeTrue();
});

it('un downgrade di rischio (critical→low) richiede approval (no auto-approve)', function () {
    $base = lowRiskManifest();
    $base['permissions'][0]['risk'] = 'critical';
    setApplied($base);

    $payload = lowRiskManifest();
    $payload['permissions'][0]['risk'] = 'low'; // declassa il permesso critical

    expect(app(ManifestRegistry::class)->submit($payload)->status)->toBe('pending_approval');
});

it('un riordino delle chiavi (dati invariati) NON è un change → approved', function () {
    setApplied(lowRiskManifest());

    $payload = lowRiskManifest();
    $payload['permissions'][0] = ['risk' => 'low', 'key' => 'report.read']; // stesse chiavi, ordine invertito

    $manifest = app(ManifestRegistry::class)->submit($payload);
    expect($manifest->status)->toBe('approved')
        ->and($manifest->diff['permissions']['changed'])->toBe([]);
});
