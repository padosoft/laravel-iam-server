<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Iam\Domain\Authorization\Models\Grant;
use Padosoft\Iam\Domain\Identity\Models\FederatedProvider;
use Padosoft\Iam\Http\Admin\Support\AdminActorResolver;
use Padosoft\Iam\Http\Admin\Support\AdminContext;

uses(RefreshDatabase::class);

// Self-contained: resolver di test via X-Test-Auth (super admin, org null).
function fedBind(): void
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
function fedGrant(string $subjectId, array $permissions): void
{
    foreach ($permissions as $perm) {
        Grant::create([
            'subject_type' => 'user', 'subject_id' => $subjectId,
            'privilege_type' => 'permission', 'privilege_key' => $perm,
        ]);
    }
}

beforeEach(fn () => fedBind());

it('rifiuta 403 fail-closed senza permesso', function () {
    $this->getJson('/api/iam/v1/federated-providers', ['X-Test-Auth' => 'adm'])->assertStatus(403);
});

it('crea un provider e NON restituisce mai il client_secret (write-only, cifrato)', function () {
    fedGrant('adm', ['iam:federated.read', 'iam:federated.manage']);

    $res = $this->postJson('/api/iam/v1/federated-providers', [
        'key' => 'google', 'driver' => 'oidc', 'client_id' => 'cid', 'client_secret' => 'super-secret',
    ], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'f1']);

    $res->assertStatus(201)
        ->assertJsonPath('data.has_secret', true)
        ->assertJsonMissingPath('data.client_secret')
        ->assertJsonMissingPath('data.client_secret_encrypted');

    // In DB il secret è cifrato (envelope JSON), mai il plaintext.
    $stored = (string) FederatedProvider::query()->where('key', 'google')->value('client_secret_encrypted');
    expect($stored)->not->toBe('super-secret')
        ->and(str_contains($stored, 'super-secret'))->toBeFalse()
        ->and(str_contains($stored, 'ciphertext'))->toBeTrue();
});

it('show e list non espongono il secret', function () {
    fedGrant('adm', ['iam:federated.read', 'iam:federated.manage']);
    $this->postJson('/api/iam/v1/federated-providers', ['key' => 'gh', 'driver' => 'socialite', 'client_secret' => 's'], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'f1']);

    $this->getJson('/api/iam/v1/federated-providers/gh', ['X-Test-Auth' => 'adm'])
        ->assertOk()->assertJsonMissingPath('data.client_secret')->assertJsonPath('data.has_secret', true);
    $this->getJson('/api/iam/v1/federated-providers', ['X-Test-Auth' => 'adm'])
        ->assertOk()->assertJsonStructure(['data', 'next_cursor']);
});

it('il test di un provider oidc senza discovery segnala issues, senza leak del secret', function () {
    fedGrant('adm', ['iam:federated.manage']);
    $this->postJson('/api/iam/v1/federated-providers', ['key' => 'oidc1', 'driver' => 'oidc', 'client_id' => 'cid', 'client_secret' => 's'], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'f1']);

    $res = $this->postJson('/api/iam/v1/federated-providers/oidc1/test', [], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 't1']);

    $res->assertOk()->assertJsonPath('data.ok', false)->assertJsonMissingPath('data.client_secret');
    expect(collect($res->json('data.issues'))->implode(' '))->toContain('discovery');
});

it('l\'update ruota il secret (write-only) e non lo restituisce', function () {
    fedGrant('adm', ['iam:federated.read', 'iam:federated.manage']);
    $this->postJson('/api/iam/v1/federated-providers', ['key' => 'g', 'driver' => 'oidc', 'client_secret' => 'old'], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'f1']);
    $oldEnc = (string) FederatedProvider::query()->where('key', 'g')->value('client_secret_encrypted');

    $this->patchJson('/api/iam/v1/federated-providers/g', ['client_secret' => 'new', 'redirect_uri' => 'https://x/cb'], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'u1'])
        ->assertOk()->assertJsonPath('data.redirect_uri', 'https://x/cb')->assertJsonMissingPath('data.client_secret');

    $newEnc = (string) FederatedProvider::query()->where('key', 'g')->value('client_secret_encrypted');
    expect($newEnc)->not->toBe($oldEnc)->and(str_contains($newEnc, 'new'))->toBeFalse();
});

it('elimina un provider', function () {
    fedGrant('adm', ['iam:federated.manage']);
    $this->postJson('/api/iam/v1/federated-providers', ['key' => 'g', 'driver' => 'oidc'], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'f1']);

    $this->deleteJson('/api/iam/v1/federated-providers/g', [], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'd1'])
        ->assertOk()->assertJsonPath('data.deleted', true);
    expect(FederatedProvider::query()->where('key', 'g')->exists())->toBeFalse();
});
