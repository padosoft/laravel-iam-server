<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Padosoft\Iam\Domain\Authorization\Models\Grant;
use Padosoft\Iam\Domain\Identity\Federation\AccountLinker;
use Padosoft\Iam\Domain\Identity\Federation\FederatedIdentityWriter;
use Padosoft\Iam\Domain\Identity\Federation\FederatedProfile;
use Padosoft\Iam\Domain\Identity\Models\FederatedIdentity;
use Padosoft\Iam\Domain\Identity\Models\FederatedProvider;
use Padosoft\Iam\Domain\Identity\Models\User;
use Padosoft\Iam\Domain\Organizations\Models\Membership;
use Padosoft\Iam\Domain\Organizations\Models\Organization;

uses(RefreshDatabase::class);

/** @param array<string, mixed>|null $jitPolicy */
function fedProvider(?array $jitPolicy = null): FederatedProvider
{
    $org = Organization::query()->create(['key' => 'acme', 'name' => 'Acme']);

    return FederatedProvider::query()->create([
        'organization_id' => $org->id,
        'key' => 'google',
        'driver' => 'socialite',
        'jit_policy' => $jitPolicy,
    ]);
}

function makeUser(string $email): User
{
    $user = new User;
    $user->forceFill(['email' => $email])->save();

    return $user;
}

function linker(): AccountLinker
{
    return app(AccountLinker::class);
}

it('un provider_subject già collegato fa il login dell\'utente', function () {
    $provider = fedProvider();
    $user = makeUser('a@acme.test');
    app(FederatedIdentityWriter::class)->write($provider, new FederatedProfile('sub-1', 'a@acme.test', true), $user->id, 'linked', null);

    $outcome = linker()->resolve($provider, new FederatedProfile('sub-1', 'a@acme.test', true));

    expect($outcome->status)->toBe('linked')->and($outcome->userId)->toBe($user->id);
});

it('NON auto-collega un account esistente via email NON verificata (anti account-takeover)', function () {
    $provider = fedProvider();
    $victim = makeUser('victim@acme.test');

    // Un attaccante presso un IdP che non verifica l'email NON deve impossessarsi dell'account.
    $outcome = linker()->resolve($provider, new FederatedProfile('attacker-sub', 'victim@acme.test', false));

    expect($outcome->status)->toBe('pending')
        ->and(FederatedIdentity::query()->where('user_id', $victim->id)->whereNull('revoked_at')->exists())->toBeFalse();
});

it('auto-collega a un utente esistente con email VERIFICATA', function () {
    $provider = fedProvider();
    $user = makeUser('user@acme.test');

    $outcome = linker()->resolve($provider, new FederatedProfile('sub-x', 'user@acme.test', true));

    expect($outcome->status)->toBe('linked')->and($outcome->userId)->toBe($user->id);
});

it('JIT: crea utente + membership + ruoli default quando nessun account ha l\'email verificata', function () {
    $provider = fedProvider(['default_roles' => ['tenant_member']]);

    $outcome = linker()->resolve($provider, new FederatedProfile('sub-new', 'new@acme.test', true, 'New User'));

    expect($outcome->status)->toBe('provisioned')->and($outcome->userId)->not->toBeNull();
    expect(User::query()->where('email', 'new@acme.test')->exists())->toBeTrue()
        ->and(Membership::query()->where('user_id', $outcome->userId)->exists())->toBeTrue()
        ->and(Grant::query()->where('subject_id', $outcome->userId)->where('privilege_key', 'tenant_member')->where('source', 'jit')->exists())->toBeTrue();
});

it('JIT: nega un dominio non in allowlist → pending', function () {
    $provider = fedProvider(['allowed_domains' => ['corp.test']]);

    $outcome = linker()->resolve($provider, new FederatedProfile('sub-d', 'user@other.test', true));

    expect($outcome->status)->toBe('pending')->and($outcome->reason)->toBe('jit_domain_not_allowed');
});

it('conflitto: email dell\'utente già legata a un subject diverso → pending', function () {
    $provider = fedProvider();
    $user = makeUser('u@acme.test');
    app(FederatedIdentityWriter::class)->write($provider, new FederatedProfile('sub-A', 'u@acme.test', true), $user->id, 'linked', null);

    $outcome = linker()->resolve($provider, new FederatedProfile('sub-B', 'u@acme.test', true));

    expect($outcome->status)->toBe('pending')->and($outcome->reason)->toBe('email_conflict');
});
