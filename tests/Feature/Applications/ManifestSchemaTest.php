<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('publishes the manifest JSON schema at a public well-known URL', function () {
    $res = $this->get('/.well-known/iam-manifest-schema.json');
    $res->assertOk();

    $schema = json_decode((string) $res->getContent(), true);
    expect($schema)->toBeArray()
        ->and($schema['$id'] ?? '')->toContain('manifest.schema.json')
        ->and($schema['properties']['schema']['const'] ?? null)->toBe('laravel-iam.manifest.v2')
        ->and($schema['required'] ?? [])->toContain('app')
        ->and($schema['properties']['permissions']['items']['properties']['key']['pattern'] ?? '')->toBe('^[a-z][a-z0-9_.-]*$');
});
