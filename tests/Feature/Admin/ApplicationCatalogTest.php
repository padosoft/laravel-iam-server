<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Padosoft\Iam\Domain\Authorization\Models\Permission;

uses(RefreshDatabase::class);

beforeEach(fn () => bindTestResolver());

it('applications/{app}/catalog lists the permission catalog and surfaces DEPRECATED entries', function () {
    submitApproveApply(validManifest()); // creates the 'warehouse' app + its permission/role catalog
    grantAdmin('adm', ['iam:applications.read']);

    // Fresh: entries exist and none are deprecated.
    $res = $this->getJson('/api/iam/v1/applications/warehouse/catalog', ['X-Test-Auth' => 'adm'])->assertOk();
    $perms = collect($res->json('data.permissions'));
    expect($perms)->not->toBeEmpty()
        ->and($perms->firstWhere('deprecated_at', '!=', null))->toBeNull();

    // Deprecate one permission (as a manifest removal would) — kept, not deleted.
    Permission::query()->where('app_key', 'warehouse')->orderBy('key')->first()?->update(['deprecated_at' => now()]);

    // The catalog now surfaces it with a deprecated_at timestamp (the console renders a badge from this).
    $res2 = $this->getJson('/api/iam/v1/applications/warehouse/catalog', ['X-Test-Auth' => 'adm'])->assertOk();
    expect(collect($res2->json('data.permissions'))->firstWhere('deprecated_at', '!=', null))->not->toBeNull();
});
