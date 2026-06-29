<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Padosoft\Iam\Domain\Applications\Manifest\ManifestApplier;
use Padosoft\Iam\Domain\Applications\Manifest\ManifestRegistry;
use Padosoft\Iam\Domain\Authorization\Models\Permission;
use Padosoft\Iam\Domain\Authorization\Models\Role;
use Padosoft\Iam\Domain\OAuth\Models\OauthClient;

uses(RefreshDatabase::class);

// submitApproveApply() vive in ApplicationsHelpers.php (incluso da tests/Pest.php).

it('apply crea Application + OAuth client + permessi + ruoli + role_permissions', function () {
    $manifest = app(ManifestRegistry::class)->submit(validManifest());
    $manifest->forceFill(['status' => 'approved'])->save();

    $app = app(ManifestApplier::class)->apply($manifest);

    expect($app->key)->toBe('warehouse')
        ->and(OauthClient::query()->where('client_id', 'cli_warehouse')->exists())->toBeTrue()
        ->and(Permission::query()->where('full_key', 'warehouse:stock.adjust')->where('requires_step_up', true)->exists())->toBeTrue()
        ->and(Role::query()->where('full_key', 'warehouse:stock_operator')->exists())->toBeTrue();

    $role = Role::query()->where('full_key', 'warehouse:stock_operator')->first();
    expect($role->permissions()->count())->toBe(2)
        ->and($manifest->fresh()->status)->toBe('applied')
        ->and($app->current_manifest_id)->toBe($manifest->id);
});

it('re-apply è idempotente (nessun duplicato)', function () {
    submitApproveApply(validManifest());
    submitApproveApply(validManifest());

    expect(Permission::query()->where('app_key', 'warehouse')->count())->toBe(2)
        ->and(Role::query()->where('app_key', 'warehouse')->count())->toBe(1)
        ->and(OauthClient::query()->where('client_id', 'cli_warehouse')->count())->toBe(1);
});

it('apply aggiorna le redirect_uris del client', function () {
    submitApproveApply(validManifest());

    $payload = validManifest();
    $payload['auth']['redirect_uris'] = ['https://warehouse.test/new-callback'];
    submitApproveApply($payload);

    $client = OauthClient::query()->where('client_id', 'cli_warehouse')->first();
    expect($client->redirect_uris)->toContain('https://warehouse.test/new-callback')
        ->and($client->redirect_uris)->not->toContain('https://warehouse.test/iam/callback');
});

it('genera il secret quando un client public diventa confidential (advisory Codex)', function () {
    $payload = validManifest();
    $payload['auth']['client_type'] = 'public';
    $payload['app']['type'] = 'spa'; // un public client tipico
    submitApproveApply($payload);

    expect(OauthClient::query()->where('client_id', 'cli_warehouse')->value('secret'))->toBeNull();

    $payload['auth']['client_type'] = 'confidential';
    $payload['app']['type'] = 'laravel';
    submitApproveApply($payload);

    expect(OauthClient::query()->where('client_id', 'cli_warehouse')->value('secret'))->not->toBeNull()
        ->and(OauthClient::query()->where('client_id', 'cli_warehouse')->value('is_confidential'))->toBeTruthy();
});

it('rifiuta l\'apply di un manifest non approved', function () {
    $manifest = app(ManifestRegistry::class)->submit(validManifest()); // pending_approval

    expect(fn () => app(ManifestApplier::class)->apply($manifest))->toThrow(RuntimeException::class);
});

it('deprecata (soft) un permesso rimosso dal manifest', function () {
    submitApproveApply(validManifest());

    $payload = validManifest();
    $payload['permissions'] = [['key' => 'stock.read', 'risk' => 'low']]; // rimuove stock.adjust
    $payload['roles'][0]['permissions'] = ['stock.read'];
    submitApproveApply($payload);

    expect(Permission::query()->where('full_key', 'warehouse:stock.adjust')->whereNotNull('deprecated_at')->exists())->toBeTrue()
        ->and(Permission::query()->where('full_key', 'warehouse:stock.read')->whereNull('deprecated_at')->exists())->toBeTrue();
});
