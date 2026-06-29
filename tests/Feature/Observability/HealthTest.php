<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('liveness /health risponde 200 senza autenticazione', function () {
    $this->getJson('/api/iam/v1/health')
        ->assertStatus(200)
        ->assertJson(['status' => 'ok']);
});

it('readiness /ready è 200 quando DB e KEK sono pronti', function () {
    // Solo lo status, niente dettaglio per-check in chiaro a un anonimo (no info disclosure).
    $this->getJson('/api/iam/v1/ready')
        ->assertStatus(200)
        ->assertExactJson(['status' => 'ready']);
});

it('readiness è 503 quando una dipendenza critica manca (KEK assente)', function () {
    config(['iam.crypto.kek' => '']);

    $this->getJson('/api/iam/v1/ready')
        ->assertStatus(503)
        ->assertExactJson(['status' => 'unavailable']);
});
