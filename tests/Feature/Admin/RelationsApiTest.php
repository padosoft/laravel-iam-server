<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Iam\Domain\Authorization\Models\Grant;
use Padosoft\Iam\Domain\Authorization\Models\Relation;
use Padosoft\Iam\Http\Admin\Support\AdminActorResolver;
use Padosoft\Iam\Http\Admin\Support\AdminContext;

uses(RefreshDatabase::class);

// Self-contained (niente helper globali condivisi fra file di test): resolver di test via X-Test-Auth.
function relBindResolver(): void
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
function relGrant(string $subjectId, array $permissions): void
{
    foreach ($permissions as $perm) {
        Grant::create([
            'subject_type' => 'user', 'subject_id' => $subjectId,
            'privilege_type' => 'permission', 'privilege_key' => $perm,
        ]);
    }
}

beforeEach(fn () => relBindResolver());

it('rifiuta 403 fail-closed la scrittura di una tupla senza permesso', function () {
    $this->postJson('/api/iam/v1/relations', [
        'subject' => ['type' => 'user', 'id' => 'usr_1'], 'relation' => 'owner', 'object' => ['type' => 'doc', 'id' => '42'],
    ], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'k1'])->assertStatus(403);
});

it('crea una tupla ReBAC (201) ed è idempotente sull\'identità', function () {
    relGrant('adm', ['iam:relations.manage']);
    $headers = ['X-Test-Auth' => 'adm'];
    $body = ['subject' => ['type' => 'user', 'id' => 'usr_1'], 'relation' => 'owner', 'object' => ['type' => 'doc', 'id' => '42']];

    $this->postJson('/api/iam/v1/relations', $body, $headers + ['Idempotency-Key' => 'k1'])
        ->assertStatus(201)->assertJsonPath('data.relation', 'owner');
    // stessa identità → nessun duplicato (idempotenza di dominio, a prescindere dall'Idempotency-Key)
    $this->postJson('/api/iam/v1/relations', $body, $headers + ['Idempotency-Key' => 'k2'])->assertStatus(201);

    expect(Relation::query()->where('subject_id', 'usr_1')->count())->toBe(1);
});

it('list-subjects e list-resources rispondono col grafo ReBAC', function () {
    relGrant('adm', ['iam:relations.manage', 'iam:decisions.explain']);
    $auth = ['X-Test-Auth' => 'adm'];
    // usr_2 membro di group:eng; group:eng editor di doc:99
    $this->postJson('/api/iam/v1/relations', ['subject' => ['type' => 'user', 'id' => 'usr_2'], 'relation' => 'member', 'object' => ['type' => 'group', 'id' => 'eng']], $auth + ['Idempotency-Key' => 'a'])->assertStatus(201);
    $this->postJson('/api/iam/v1/relations', ['subject' => ['type' => 'group', 'id' => 'eng'], 'relation' => 'editor', 'object' => ['type' => 'doc', 'id' => '99']], $auth + ['Idempotency-Key' => 'b'])->assertStatus(201);

    $subjects = $this->postJson('/api/iam/v1/decisions/list-subjects', ['relation' => 'editor', 'object' => ['type' => 'doc', 'id' => '99']], $auth + ['Idempotency-Key' => 'ls'])
        ->assertOk()->json('data.subjects');
    expect(collect($subjects)->pluck('id')->all())->toContain('usr_2');

    $resources = $this->postJson('/api/iam/v1/decisions/list-resources', ['subject' => ['type' => 'user', 'id' => 'usr_2'], 'relation' => 'editor'], $auth + ['Idempotency-Key' => 'lr'])
        ->assertOk()->json('data.resources');
    expect(collect($resources)->pluck('id')->all())->toContain('99');
});

it('revoca una tupla (DELETE) in modo idempotente', function () {
    relGrant('adm', ['iam:relations.manage']);
    $auth = ['X-Test-Auth' => 'adm'];
    $body = ['subject' => ['type' => 'user', 'id' => 'usr_1'], 'relation' => 'owner', 'object' => ['type' => 'doc', 'id' => '42']];
    $this->postJson('/api/iam/v1/relations', $body, $auth + ['Idempotency-Key' => 'c'])->assertStatus(201);

    $this->deleteJson('/api/iam/v1/relations', $body, $auth + ['Idempotency-Key' => 'd'])
        ->assertOk()->assertJsonPath('data.revoked', true);
    // seconda revoca: idempotente, nessuna tupla attiva
    $this->deleteJson('/api/iam/v1/relations', $body, $auth + ['Idempotency-Key' => 'e'])
        ->assertOk()->assertJsonPath('data.revoked', false);
});
