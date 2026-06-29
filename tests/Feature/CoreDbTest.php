<?php

declare(strict_types=1);

use Illuminate\Database\QueryException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Padosoft\Iam\Domain\Authorization\Models\Grant;
use Padosoft\Iam\Domain\Identity\Models\User;
use Padosoft\Iam\Domain\Organizations\Models\Membership;
use Padosoft\Iam\Domain\Organizations\Models\Organization;

uses(RefreshDatabase::class);

/** @return array<string, mixed> */
function grantData(array $overrides = []): array
{
    return array_merge([
        'subject_type' => 'user',
        'subject_id' => 'usr_1',
        'privilege_type' => 'role',
        'privilege_key' => 'app:role_a',
    ], $overrides);
}

// --- Caso felice ---

it('crea users/org/membership con ULID e relazioni', function () {
    $user = User::create(['email' => 'a@example.com', 'name' => 'A']);
    $org = Organization::create(['key' => 'acme', 'name' => 'Acme']);
    $membership = Membership::create([
        'organization_id' => $org->id,
        'user_id' => $user->id,
    ]);

    expect($user->id)->toBeString()->toHaveLength(26)
        ->and($user->status)->toBe('active')
        ->and($membership->user->email)->toBe('a@example.com')
        ->and($membership->organization->key)->toBe('acme')
        ->and($org->memberships()->count())->toBe(1);
});

it('un grant nasce IGA-ready con default sicuri', function () {
    $org = Organization::create(['key' => 'acme', 'name' => 'Acme']);
    $grant = Grant::create(grantData([
        'organization_id' => $org->id,
        'application_key' => 'warehouse',
        'privilege_key' => 'warehouse:stock_operator',
        'conditions_json' => ['amount' => ['<=' => 500]],
        'source' => 'manual_admin',
    ]));

    expect($grant->effect)->toBe('permit')
        ->and($grant->is_privileged)->toBeFalse()
        ->and($grant->activation_required)->toBeFalse()
        ->and($grant->valid_until)->toBeNull()
        ->and($grant->conditions_json)->toBe(['amount' => ['<=' => 500]])
        ->and($grant->organization->key)->toBe('acme');
});

// --- Negativi obbligatori (CLAUDE.md): denial, tenant isolation, fail-closed ---

it('scopeActive esclude i grant revocati', function () {
    $active = Grant::create(grantData(['privilege_key' => 'app:role_active']));
    $revoked = Grant::create(grantData(['privilege_key' => 'app:role_revoked']));
    $revoked->revoke('test-actor');

    expect(Grant::active()->count())->toBe(1)
        ->and(Grant::active()->first()->id)->toBe($active->id);
});

it('scopeActive esclude i grant fuori finestra di validità (fail-closed)', function () {
    Grant::create(grantData(['privilege_key' => 'app:expired', 'valid_until' => now()->subDay()]));
    Grant::create(grantData(['privilege_key' => 'app:future', 'valid_from' => now()->addDay()]));
    $valid = Grant::create(grantData(['privilege_key' => 'app:valid', 'valid_until' => now()->addDay()]));

    expect(Grant::active()->count())->toBe(1)
        ->and(Grant::active()->first()->id)->toBe($valid->id);
});

it('scopeActive: un grant activation_required è inattivo finché non attivato (fail-closed PIM)', function () {
    $pending = Grant::create(grantData(['privilege_key' => 'app:pim', 'activation_required' => true]));

    expect(Grant::active()->count())->toBe(0);

    $pending->activate();

    expect(Grant::active()->count())->toBe(1);
});

it('isola i grant per organizzazione (tenant isolation)', function () {
    $a = Organization::create(['key' => 'a', 'name' => 'A']);
    $b = Organization::create(['key' => 'b', 'name' => 'B']);
    Grant::create(grantData(['organization_id' => $a->id]));
    Grant::create(grantData(['organization_id' => $b->id]));

    expect($a->grants()->count())->toBe(1)
        ->and($b->grants()->count())->toBe(1)
        ->and($a->grants()->first()->organization_id)->toBe($a->id);
});

it('eliminare un org elimina i suoi grant (no orphan cross-tenant)', function () {
    $org = Organization::create(['key' => 'acme', 'name' => 'Acme']);
    Grant::create(grantData(['organization_id' => $org->id]));

    expect(Grant::count())->toBe(1);

    $org->delete();

    expect(Grant::count())->toBe(0);
});

it('persiste un grant con effect deny', function () {
    $deny = Grant::create(grantData(['privilege_key' => 'app:secret', 'effect' => 'deny']));

    expect($deny->effect)->toBe('deny')
        ->and(Grant::where('effect', 'deny')->count())->toBe(1);
});

it('rifiuta grant duplicati con stessa identità (unique identity_hash)', function () {
    Grant::create(grantData(['organization_id' => null]));

    expect(fn () => Grant::create(grantData(['organization_id' => null])))
        ->toThrow(QueryException::class);
});

it('identity_hash non collide tra valori con separatori (no injection)', function () {
    // Sotto implode("|") questi due grant collidono; con json_encode no.
    $a = Grant::create(grantData(['privilege_key' => 'a|b', 'resource_ref' => 'c']));
    $b = Grant::create(grantData(['privilege_key' => 'a', 'resource_ref' => 'b|c']));

    expect($a->identity_hash)->not->toBe($b->identity_hash)
        ->and(Grant::count())->toBe(2);
});

it('email è unica', function () {
    User::create(['email' => 'dup@example.com']);

    expect(fn () => User::create(['email' => 'dup@example.com']))
        ->toThrow(QueryException::class);
});

// --- Sicurezza: revoke() e changeStatus() come unici entry point controllati ---

it('revoke() imposta revoked_at e revoked_by tramite metodo controllato', function () {
    $grant = Grant::create(grantData());
    expect(Grant::active()->count())->toBe(1);

    $grant->revoke('admin-user');

    $grant->refresh();
    expect($grant->revoked_at)->not->toBeNull()
        ->and($grant->revoked_by)->toBe('admin-user')
        ->and(Grant::active()->count())->toBe(0);
});

it('revoked_at non è mass-assignable (sicurezza: no bypass revoca via fill)', function () {
    $grant = Grant::create(grantData());
    $grant->revoke('admin-user');

    // Tentativo di ripristinare la revoca via fill deve essere silenziosamente ignorato.
    $grant->fill(['revoked_at' => null, 'revoked_by' => null])->save();
    $grant->refresh();

    expect($grant->revoked_at)->not->toBeNull();
});

it('changeStatus() cambia lo stato utente e scrive audit UserStatusChange', function () {
    $user = User::create(['email' => 'b@example.com']);
    expect($user->status)->toBe('active')
        ->and($user->statusChanges()->count())->toBe(0);

    $user->changeStatus('suspended', 'admin-actor', 'violazione policy');

    $user->refresh();
    expect($user->status)->toBe('suspended')
        ->and($user->statusChanges()->count())->toBe(1);

    $change = $user->statusChanges()->first();
    expect($change->from_status)->toBe('active')
        ->and($change->to_status)->toBe('suspended')
        ->and($change->actor_ref)->toBe('admin-actor')
        ->and($change->reason)->toBe('violazione policy');
});

it('status non è mass-assignable (sicurezza: no bypass audit via fill)', function () {
    $user = User::create(['email' => 'c@example.com']);

    // fill() deve ignorare status silenziosamente.
    $user->fill(['status' => 'deactivated'])->save();
    $user->refresh();

    expect($user->status)->toBe('active')
        ->and($user->statusChanges()->count())->toBe(0);
});
