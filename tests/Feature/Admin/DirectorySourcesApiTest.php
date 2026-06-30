<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Iam\Domain\Authorization\Models\Grant;
use Padosoft\Iam\Domain\Directory\Models\DirectorySource;
use Padosoft\Iam\Http\Admin\Support\AdminActorResolver;
use Padosoft\Iam\Http\Admin\Support\AdminContext;

uses(RefreshDatabase::class);

// Self-contained: resolver di test via X-Test-Auth (super admin, org null).
function dirBind(): void
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
function dirGrant(string $subjectId, array $permissions): void
{
    foreach ($permissions as $perm) {
        Grant::create([
            'subject_type' => 'user', 'subject_id' => $subjectId,
            'privilege_type' => 'permission', 'privilege_key' => $perm,
        ]);
    }
}

beforeEach(function () {
    dirBind();
    config()->set('iam.directory.enabled', false); // default: modulo -directory assente
});

it('rifiuta 403 fail-closed senza permesso', function () {
    $this->getJson('/api/iam/v1/directory-sources', ['X-Test-Auth' => 'adm'])->assertStatus(403);
});

it('CRUD di una sorgente con bind_secret write-only (mai restituito)', function () {
    dirGrant('adm', ['iam:directory.read', 'iam:directory.manage']);
    $h = ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'd1'];

    $res = $this->postJson('/api/iam/v1/directory-sources', [
        'key' => 'corp-ad', 'name' => 'Corp AD', 'host' => 'ldaps://ad.local', 'base_dn' => 'dc=corp',
        'bind_dn' => 'cn=svc', 'bind_secret' => 'ldap-pass',
    ], $h);

    $res->assertStatus(201)
        ->assertJsonPath('data.has_bind_secret', true)
        ->assertJsonMissingPath('data.bind_secret')
        ->assertJsonMissingPath('data.bind_secret_encrypted');

    $stored = DirectorySource::query()->where('key', 'corp-ad')->firstOrFail();
    expect(json_encode($stored->bind_secret_encrypted))->not->toContain('ldap-pass');

    $this->getJson('/api/iam/v1/directory-sources/corp-ad', ['X-Test-Auth' => 'adm'])
        ->assertOk()->assertJsonMissingPath('data.bind_secret')->assertJsonPath('data.has_bind_secret', true);
});

it('trigger sync → 409 quando il modulo -directory non è attivo', function () {
    dirGrant('adm', ['iam:directory.manage']);
    $src = DirectorySource::create(['key' => 's', 'name' => 'S', 'host' => 'h', 'base_dn' => 'dc=x']);

    $this->postJson("/api/iam/v1/directory-sources/{$src->id}/sync", [], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'sy1'])
        ->assertStatus(409);
});

it('trigger sync → 202 quando il modulo -directory è attivo', function () {
    config()->set('iam.directory.enabled', true);
    dirGrant('adm', ['iam:directory.manage']);
    $src = DirectorySource::create(['key' => 's', 'name' => 'S', 'host' => 'h', 'base_dn' => 'dc=x']);

    $this->postJson("/api/iam/v1/directory-sources/{$src->id}/sync", [], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'sy1'])
        ->assertStatus(202)->assertJsonPath('data.sync_status', 'queued');
    expect(DirectorySource::query()->find($src->id)->last_sync_status)->toBe('queued');
});

it('trigger test → 409 quando il modulo non è attivo, 200 quando attivo (no secret leak)', function () {
    dirGrant('adm', ['iam:directory.manage']);
    $src = DirectorySource::create(['key' => 's', 'name' => 'S', 'host' => 'h', 'base_dn' => 'dc=x']);

    $this->postJson("/api/iam/v1/directory-sources/{$src->id}/test", [], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 't0'])
        ->assertStatus(409);

    config()->set('iam.directory.enabled', true);
    $this->postJson("/api/iam/v1/directory-sources/{$src->id}/test", [], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 't1'])
        ->assertOk()->assertJsonMissingPath('data.bind_secret');
});
