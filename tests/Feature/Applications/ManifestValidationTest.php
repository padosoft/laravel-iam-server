<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

// validManifest() / manifests() vivono in ApplicationsHelpers.php (incluso da tests/Pest.php).

it('valida un manifest corretto (nessun errore, non rejected)', function () {
    $manifest = manifests()->submit(validManifest(), 'admin@iam.test');

    expect($manifest->validation_errors)->toBeNull()
        ->and($manifest->version)->toBe(1)
        ->and($manifest->status)->not->toBe('rejected');
});

it('rifiuta una redirect_uri non-https (no javascript:/http arbitrario)', function () {
    foreach (['http://attacker.test/cb', 'javascript:alert(1)', 'data:text/html,x'] as $bad) {
        $payload = validManifest();
        $payload['auth']['redirect_uris'] = [$bad];
        expect(manifests()->submit($payload)->status)->toBe('rejected');
    }
});

it('rifiuta permission con key duplicata', function () {
    $payload = validManifest();
    $payload['permissions'][] = ['key' => 'stock.read', 'risk' => 'critical']; // duplicato di stock.read

    expect(manifests()->submit($payload)->status)->toBe('rejected');
});

it('incrementa la versione per la stessa app', function () {
    manifests()->submit(validManifest());
    $second = manifests()->submit(validManifest());

    expect($second->version)->toBe(2);
});

it('rifiuta un manifest con schema errato', function () {
    $payload = validManifest();
    $payload['schema'] = 'laravel-iam.manifest.v1';

    expect(manifests()->submit($payload)->status)->toBe('rejected');
});

it('rifiuta un manifest senza app.name', function () {
    $payload = validManifest();
    unset($payload['app']['name']);

    $manifest = manifests()->submit($payload);
    expect($manifest->status)->toBe('rejected')
        ->and($manifest->validation_errors)->toContain('app.name richiesto');
});

it('rifiuta una app.key malformata', function () {
    $payload = validManifest();
    $payload['app']['key'] = 'Warehouse!'; // maiuscole + carattere non ammesso

    expect(manifests()->submit($payload)->status)->toBe('rejected');
});

it('rifiuta un ruolo che referenzia un permission non dichiarato', function () {
    $payload = validManifest();
    $payload['roles'][0]['permissions'][] = 'stock.delete'; // non dichiarato

    $manifest = manifests()->submit($payload);
    expect($manifest->status)->toBe('rejected')
        ->and(collect($manifest->validation_errors)->contains(fn (string $e): bool => str_contains($e, 'stock.delete')))->toBeTrue();
});

it('rifiuta una redirect_uri con wildcard (no open redirect)', function () {
    $payload = validManifest();
    $payload['auth']['redirect_uris'] = ['https://*.warehouse.test/callback'];

    expect(manifests()->submit($payload)->status)->toBe('rejected');
});

it('rifiuta un app.type sconosciuto (typo → fail-closed, advisory)', function () {
    $payload = validManifest();
    $payload['app']['type'] = 'servcie'; // typo di "service"

    $manifest = manifests()->submit($payload);
    expect($manifest->status)->toBe('rejected')
        ->and(collect($manifest->validation_errors)->contains(fn (string $e): bool => str_contains($e, 'app.type')))->toBeTrue();
});

it('ammette una redirect_uri http verso localhost IPv6 (dev)', function () {
    $payload = validManifest();
    $payload['auth']['redirect_uris'] = ['http://[::1]:8080/callback'];

    expect(manifests()->submit($payload)->status)->not->toBe('rejected');
});
