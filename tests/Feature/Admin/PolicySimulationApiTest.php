<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Iam\Domain\Applications\Manifest\ManifestRegistry;
use Padosoft\Iam\Domain\Authorization\Models\Grant;
use Padosoft\Iam\Domain\Authorization\Models\PolicyProbe;
use Padosoft\Iam\Domain\Authorization\Models\Role;
use Padosoft\Iam\Http\Admin\Support\AdminActorResolver;
use Padosoft\Iam\Http\Admin\Support\AdminContext;

uses(RefreshDatabase::class);

function simBind(): void
{
    app()->bind(AdminActorResolver::class, fn (): AdminActorResolver => new class implements AdminActorResolver
    {
        public function resolve(Request $request): ?AdminContext
        {
            $id = $request->headers->get('X-Test-Auth');

            return is_string($id) && $id !== '' ? new AdminContext(new SubjectRef('user', $id)) : null;
        }
    });
}

/** @param list<string> $permissions */
function simGrant(string $subjectId, array $permissions): void
{
    foreach ($permissions as $perm) {
        Grant::create([
            'subject_type' => 'user', 'subject_id' => $subjectId,
            'privilege_type' => 'permission', 'privilege_key' => $perm,
        ]);
    }
}

beforeEach(fn () => simBind());

it('misurare un blast radius richiede un permesso PROPRIO, non policies.read', function () {
    // Misurare esegue davvero il cambiamento in transazione: costa lock e
    // scritture, anche se poi annulla tutto. Non è leggere un catalogo.
    simGrant('adm', ['iam:policies.read']);

    $manifest = app(ManifestRegistry::class)->submit(validManifest());
    $manifest->forceFill(['status' => 'approved'])->save();

    $this->postJson("/api/iam/v1/manifests/{$manifest->id}/blast-radius", [], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'b0'])
        ->assertStatus(403);
});

it('registra una sonda in modo idempotente e ne aggiorna l\'aspettativa', function () {
    simGrant('adm', ['iam:policies.simulate', 'iam:policies.read']);

    $body = [
        'subject' => ['type' => 'user', 'id' => 'usr_1'],
        'permission' => 'warehouse:stock.read',
        'application_key' => 'warehouse',
        'label' => 'lo stock lo legge sempre',
    ];

    $first = $this->postJson('/api/iam/v1/policy/probes', $body, ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'p1']);
    $first->assertStatus(201);

    $second = $this->postJson('/api/iam/v1/policy/probes', $body + ['expected_allowed' => true], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'p2']);
    $second->assertOk();

    expect(PolicyProbe::query()->count())->toBe(1)
        ->and($second->json('data.id'))->toBe($first->json('data.id'))
        ->and(PolicyProbe::query()->first()?->expected_allowed)->toBeTrue();
});

it('un blast radius senza sonde è 422, non "nessun impatto"', function () {
    // Un report su zero sonde direbbe "0 cambiamenti" e non significherebbe nulla.
    simGrant('adm', ['iam:policies.simulate']);

    $manifest = app(ManifestRegistry::class)->submit(validManifest());
    $manifest->forceFill(['status' => 'approved'])->save();

    $this->postJson("/api/iam/v1/manifests/{$manifest->id}/blast-radius", [], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'b1'])
        ->assertStatus(422);
});

it('mostra chi guadagnerebbe autorità applicando un manifest — e NON lo applica', function () {
    simGrant('adm', ['iam:policies.simulate']);

    // Il soggetto ha già il RUOLO; il manifest è ciò che gli attacca il permesso.
    simGrant('usr_1', ['warehouse:stock_operator']);
    Grant::query()->where('privilege_key', 'warehouse:stock_operator')
        ->update(['privilege_type' => 'role', 'application_key' => 'warehouse']);

    PolicyProbe::query()->create([
        'id' => PolicyProbe::newId(),
        'application_key' => 'warehouse',
        'subject_type' => 'user', 'subject_id' => 'usr_1',
        'permission' => 'warehouse:stock.read',
        'current_aal' => 'aal1',
        'source' => PolicyProbe::SOURCE_MANUAL,
        'probe_hash' => PolicyProbe::hashOf(new SubjectRef('user', 'usr_1'), 'warehouse:stock.read', null, [], null, 'aal1', 'warehouse'),
    ]);

    $manifest = app(ManifestRegistry::class)->submit(validManifest());
    $manifest->forceFill(['status' => 'approved'])->save();

    $res = $this->postJson("/api/iam/v1/manifests/{$manifest->id}/blast-radius", [], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'b2']);

    $res->assertOk();
    expect($res->json('data.counts.granted'))->toBe(1)
        ->and($res->json('data.changes.0.kind'))->toBe('granted')
        // …e il manifest NON è stato applicato: nessun ruolo creato, nessuna app.
        ->and(Role::query()->where('full_key', 'warehouse:stock_operator')->exists())->toBeFalse()
        ->and($manifest->fresh()?->status)->toBe('approved');
});

it('la regressione risponde 422 quando la policy è divergente, 200 quando torna', function () {
    simGrant('adm', ['iam:policies.read', 'iam:policies.simulate']);

    PolicyProbe::query()->create([
        'id' => PolicyProbe::newId(),
        'application_key' => 'warehouse',
        'subject_type' => 'user', 'subject_id' => 'usr_1',
        'permission' => 'warehouse:stock.read',
        'current_aal' => 'aal1',
        'expected_allowed' => true,
        'source' => PolicyProbe::SOURCE_MANUAL,
        'probe_hash' => PolicyProbe::hashOf(new SubjectRef('user', 'usr_1'), 'warehouse:stock.read', null, [], null, 'aal1', 'warehouse'),
    ]);

    $this->postJson('/api/iam/v1/policy/regression', [], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'r0'])
        ->assertStatus(422)
        ->assertJsonPath('data.passed', false);

    simGrant('usr_1', ['warehouse:stock.read']);
    Grant::query()->where('subject_id', 'usr_1')->update(['application_key' => 'warehouse']);

    $this->postJson('/api/iam/v1/policy/regression', [], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'r1'])
        ->assertOk()
        ->assertJsonPath('data.passed', true);
});
