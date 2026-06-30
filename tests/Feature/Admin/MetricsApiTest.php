<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Iam\Domain\Audit\Models\AuditEvent;
use Padosoft\Iam\Domain\Audit\Pii\AuditRecorder;
use Padosoft\Iam\Domain\Authorization\Models\Grant;
use Padosoft\Iam\Http\Admin\Support\AdminActorResolver;
use Padosoft\Iam\Http\Admin\Support\AdminContext;

uses(RefreshDatabase::class);

// Self-contained: resolver di test via X-Test-Auth, org-bound opzionale.
function metBind(?string $org = null): void
{
    app()->bind(AdminActorResolver::class, fn (): AdminActorResolver => new class($org) implements AdminActorResolver
    {
        public function __construct(private ?string $org) {}

        public function resolve(Request $request): ?AdminContext
        {
            $id = $request->headers->get('X-Test-Auth');

            return is_string($id) && $id !== '' ? new AdminContext(new SubjectRef('user', $id), $this->org) : null;
        }
    });
}

/** @param list<string> $permissions */
function metGrant(string $subjectId, array $permissions): void
{
    foreach ($permissions as $perm) {
        Grant::create([
            'subject_type' => 'user', 'subject_id' => $subjectId,
            'privilege_type' => 'permission', 'privilege_key' => $perm,
        ]);
    }
}

function metSeedEvent(string $type, ?string $org = null, ?string $assurance = null): AuditEvent
{
    return app(AuditRecorder::class)->record([
        'stream' => $org ?? 'global',
        'event_type' => $type,
        'organization_id' => $org,
        'actor_assurance' => $assurance,
    ]);
}

it('rifiuta 403 fail-closed senza permesso', function () {
    metBind();
    $this->getJson('/api/iam/v1/metrics/grants', ['X-Test-Auth' => 'adm'])->assertStatus(403);
});

it('metrics/grants conta active/revoked/expired/privileged/stale', function () {
    metBind();
    metGrant('adm', ['iam:metrics.read']);   // 1 grant attivo (l'admin stesso)
    Grant::create(['subject_type' => 'user', 'subject_id' => 'u', 'privilege_type' => 'role', 'privilege_key' => 'warehouse:admin', 'is_privileged' => true]); // attivo, privileged
    Grant::create(['subject_type' => 'user', 'subject_id' => 'u', 'privilege_type' => 'permission', 'privilege_key' => 'p.expired', 'valid_until' => now()->subDay()]); // scaduto
    Grant::create(['subject_type' => 'user', 'subject_id' => 'u', 'privilege_type' => 'permission', 'privilege_key' => 'p.revoked'])->revoke('admin'); // revocato

    $res = $this->getJson('/api/iam/v1/metrics/grants', ['X-Test-Auth' => 'adm']);

    $res->assertOk()
        ->assertJsonPath('data.active', 2)       // admin + privileged
        ->assertJsonPath('data.privileged', 1)
        ->assertJsonPath('data.expired', 1)
        ->assertJsonPath('data.revoked', 1)
        ->assertJsonPath('data.stale', 2);       // entrambi gli attivi mai usati (last_used_at null)
});

it('metrics/decisions aggrega allow/deny ed è bounded sulla finestra temporale', function () {
    metBind();
    metGrant('adm', ['iam:metrics.read']);
    metSeedEvent('iam.access.granted');
    metSeedEvent('iam.access.granted');
    metSeedEvent('iam.access.granted');
    metSeedEvent('iam.access.denied');
    metSeedEvent('iam.policy.rejected');
    metSeedEvent('iam.stepup.granted', null, 'aal2');
    // Evento fuori finestra (60 giorni fa): NON deve essere contato col default (30 giorni).
    $old = metSeedEvent('iam.access.denied');
    AuditEvent::query()->whereKey($old->uuid)->update(['occurred_at' => now()->subDays(60)]);

    $res = $this->getJson('/api/iam/v1/metrics/decisions', ['X-Test-Auth' => 'adm']);

    $res->assertOk()
        ->assertJsonPath('data.total', 6)        // l'evento fuori finestra è escluso (bounded)
        ->assertJsonPath('data.deny', 2)         // denied + rejected
        ->assertJsonPath('data.allow', 4)
        ->assertJsonPath('data.step_up', 1);
});

it('metrics/audit espone by_event_type e outbox lag', function () {
    metBind();
    metGrant('adm', ['iam:metrics.read']);
    metSeedEvent('iam.thing.created');
    DB::table('iam_outbox')->insert([
        'id' => (string) Str::ulid(), 'event_type' => 'x', 'stream' => 'global',
        'payload_json' => json_encode(['a' => 1]), 'status' => 'pending', 'created_at' => now(),
    ]);

    $res = $this->getJson('/api/iam/v1/metrics/audit', ['X-Test-Auth' => 'adm']);

    $res->assertOk();
    expect($res->json('data.outbox_lag'))->toBe(1)
        ->and($res->json('data.by_event_type'))->toHaveKey('iam.thing.created');
});

it('metrics/decisions è tenant-scoped: un admin di org_a non vede gli eventi di org_b', function () {
    metBind('org_a');
    metGrant('adm', ['iam:metrics.read']);
    metSeedEvent('iam.access.denied', 'org_a');
    metSeedEvent('iam.access.denied', 'org_b');
    metSeedEvent('iam.access.denied', 'org_b');

    $res = $this->getJson('/api/iam/v1/metrics/decisions', ['X-Test-Auth' => 'adm']);

    $res->assertOk()->assertJsonPath('data.total', 1)->assertJsonPath('data.deny', 1);
});
