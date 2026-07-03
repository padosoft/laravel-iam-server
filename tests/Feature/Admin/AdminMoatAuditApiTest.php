<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Padosoft\Iam\Domain\Applications\Manifest\ManifestRegistry;
use Padosoft\Iam\Domain\Audit\Pii\AuditRecorder;

uses(RefreshDatabase::class);

// bindTestResolver()/grantAdmin() globali (AdminUsersApiTest.php); validManifest()/submitApproveApply()
// globali (Applications/ApplicationsHelpers.php caricato da Pest.php).
beforeEach(fn () => bindTestResolver());

it('applications: elenca e mostra le app del registry', function () {
    submitApproveApply(validManifest()); // crea l'app "warehouse"
    grantAdmin('adm', ['iam:applications.read']);

    $this->getJson('/api/iam/v1/applications', ['X-Test-Auth' => 'adm'])
        ->assertOk()->assertJsonPath('data.0.key', 'warehouse');

    $this->getJson('/api/iam/v1/applications/warehouse', ['X-Test-Auth' => 'adm'])
        ->assertOk()->assertJsonPath('data.key', 'warehouse');
});

it('applications/{app}/manifest ritorna il manifest corrente applicato', function () {
    submitApproveApply(validManifest());
    grantAdmin('adm', ['iam:applications.read']);

    $this->getJson('/api/iam/v1/applications/warehouse/manifest', ['X-Test-Auth' => 'adm'])
        ->assertOk()->assertJsonPath('data.application_key', 'warehouse');
});

it('manifests: submit via API ritorna 201', function () {
    grantAdmin('adm', ['iam:manifests.submit']);

    $res = $this->postJson('/api/iam/v1/applications/warehouse/manifests', ['manifest' => validManifest()], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'm1']);

    $res->assertStatus(201)->assertJsonPath('data.application_key', 'warehouse');
});

it('manifests: approve poi apply crea/aggiorna l\'applicazione', function () {
    $manifest = app(ManifestRegistry::class)->submit(validManifest());
    grantAdmin('adm', ['iam:manifests.approve', 'iam:manifests.apply']);

    $this->postJson("/api/iam/v1/manifests/{$manifest->id}/approve", [], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'm2'])
        ->assertOk();
    $this->postJson("/api/iam/v1/manifests/{$manifest->id}/apply", [], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'm3'])
        ->assertOk()->assertJsonStructure(['data' => ['application_id']]);
});

it('manifests senza permesso è 403', function () {
    grantAdmin('adm', ['iam:manifests.read']);
    $manifest = app(ManifestRegistry::class)->submit(validManifest());

    $this->postJson("/api/iam/v1/manifests/{$manifest->id}/apply", [], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'm4'])
        ->assertStatus(403);
});

it('audit: elenca gli eventi e verifica la hash-chain', function () {
    $rec = app(AuditRecorder::class);
    $rec->record(['stream' => 'admin', 'event_type' => 'iam.test.one']);
    $rec->record(['stream' => 'admin', 'event_type' => 'iam.test.two']);
    grantAdmin('adm', ['iam:audit.read']);

    $this->getJson('/api/iam/v1/audit/events?stream=admin', ['X-Test-Auth' => 'adm'])
        ->assertOk()->assertJsonStructure(['data', 'next_cursor']);

    $this->postJson('/api/iam/v1/audit/verify-chain?stream=admin', [], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'v1'])
        ->assertOk()->assertJsonPath('data.valid', true);
});

it('audit: il summary espone actor_user_id (colonna Actor)', function () {
    app(AuditRecorder::class)->record([
        'stream' => 'auth', 'event_type' => 'auth.login.succeeded',
        'actor_user_id' => 'usr_actor', 'target_type' => 'user', 'target_id' => 'usr_actor',
    ]);
    grantAdmin('adm', ['iam:audit.read']);

    $res = $this->getJson('/api/iam/v1/audit/events?stream=auth', ['X-Test-Auth' => 'adm']);

    $res->assertOk();
    expect($res->json('data.0.actor_user_id'))->toBe('usr_actor');
});

it('audit: espone ip/user_agent in chiaro SOLO con ip_mode/ua_mode = full', function () {
    config(['iam.audit.ip_mode' => 'full', 'iam.audit.ua_mode' => 'full']);
    app(AuditRecorder::class)->record(['stream' => 'admin', 'event_type' => 'iam.test.ip'], [], null, '198.51.100.9', 'UA-Rec');
    grantAdmin('adm', ['iam:audit.read']);

    $res = $this->getJson('/api/iam/v1/audit/events?stream=admin', ['X-Test-Auth' => 'adm'])->assertOk();

    expect($res->json('data.0.ip'))->toBe('198.51.100.9')
        ->and($res->json('data.0.user_agent'))->toBe('UA-Rec');
});

it('audit: in modalità hash (default) NON espone ip/user_agent leggibili', function () {
    config(['iam.audit.ip_mode' => 'hash', 'iam.audit.ua_mode' => 'hash']);
    app(AuditRecorder::class)->record(['stream' => 'admin', 'event_type' => 'iam.test.ip'], [], null, '198.51.100.9', 'UA-Rec');
    grantAdmin('adm', ['iam:audit.read']);

    $res = $this->getJson('/api/iam/v1/audit/events?stream=admin', ['X-Test-Auth' => 'adm'])->assertOk();

    expect($res->json('data.0.ip'))->toBeNull()
        ->and($res->json('data.0.user_agent'))->toBeNull();
});
