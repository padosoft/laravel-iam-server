<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Padosoft\Iam\Domain\Applications\Manifest\ManifestApplier;
use Padosoft\Iam\Domain\Applications\Manifest\ManifestRegistry;
use Padosoft\Iam\Domain\Applications\Models\Application;
use Padosoft\Iam\Domain\OAuth\Models\OauthClient;
use Padosoft\Iam\Domain\Organizations\Models\Organization;

uses(RefreshDatabase::class);

it('il comando iam:manifest:apply applica un manifest con --approve', function () {
    $file = sys_get_temp_dir().'/iam-manifest-'.bin2hex(random_bytes(4)).'.json';
    file_put_contents($file, json_encode(validManifest()));

    $this->artisan('iam:manifest:apply', ['file' => $file, '--approve' => true])->assertSuccessful();

    expect(Application::query()->where('key', 'warehouse')->exists())->toBeTrue()
        ->and(OauthClient::query()->where('client_id', 'cli_warehouse')->exists())->toBeTrue();

    @unlink($file);
});

it('genera un secret per un client confidential nuovo (advisory)', function () {
    $applier = app(ManifestApplier::class);
    $manifest = app(ManifestRegistry::class)->submit(validManifest());
    $manifest->forceFill(['status' => 'approved'])->save();

    $applier->apply($manifest);

    expect($applier->generatedSecret())->toBeString()
        ->and(OauthClient::query()->where('client_id', 'cli_warehouse')->value('secret'))->not->toBeNull();
});

it('apply NON può cambiare l\'organizzazione di un\'app esistente (anti hijack, advisory)', function () {
    $orgA = Organization::query()->create(['key' => 'org-a', 'name' => 'A']);
    $orgB = Organization::query()->create(['key' => 'org-b', 'name' => 'B']);

    $m1 = app(ManifestRegistry::class)->submit(validManifest(), null, $orgA->id);
    $m1->forceFill(['status' => 'approved'])->save();
    app(ManifestApplier::class)->apply($m1);

    $m2 = app(ManifestRegistry::class)->submit(validManifest(), null, $orgB->id);
    $m2->forceFill(['status' => 'approved'])->save();

    expect(fn () => app(ManifestApplier::class)->apply($m2))->toThrow(RuntimeException::class);
});

it('il rollback ripristina le redirect_uris della versione precedente', function () {
    submitApproveApply(validManifest());

    $payload = validManifest();
    $payload['auth']['redirect_uris'] = ['https://warehouse.test/v2-callback'];
    submitApproveApply($payload);

    $application = app(ManifestRegistry::class)->rollback('warehouse', approved: true);

    expect($application)->not->toBeNull();
    $client = OauthClient::query()->where('client_id', 'cli_warehouse')->first();
    expect($client->redirect_uris)->toContain('https://warehouse.test/iam/callback')
        ->and($client->redirect_uris)->not->toContain('https://warehouse.test/v2-callback');
});

it('il rollback verso una versione sensibile richiede approvazione esplicita (advisory)', function () {
    submitApproveApply(validManifest());

    $payload = validManifest();
    $payload['auth']['redirect_uris'] = ['https://warehouse.test/v2-callback'];
    submitApproveApply($payload);

    expect(fn () => app(ManifestRegistry::class)->rollback('warehouse'))
        ->toThrow(RuntimeException::class);
});

it('rollback senza una versione precedente ritorna null', function () {
    submitApproveApply(validManifest());

    expect(app(ManifestRegistry::class)->rollback('warehouse'))->toBeNull();
});
