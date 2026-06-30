<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Iam\Domain\Authorization\Models\Grant;
use Padosoft\Iam\Domain\Authorization\Models\Relation;
use Padosoft\Iam\Domain\Authorization\Pdp\NativeReBacResolver;
use Padosoft\Iam\Domain\Authorization\Pdp\ResourceRef;
use Padosoft\Iam\Domain\Authorization\Relations\RelationWriter;
use Padosoft\Iam\Domain\Groups\Models\Group;
use Padosoft\Iam\Domain\Organizations\Models\Organization;
use Padosoft\Iam\Http\Admin\Support\AdminActorResolver;
use Padosoft\Iam\Http\Admin\Support\AdminContext;

uses(RefreshDatabase::class);

// Self-contained: resolver org-bound; il ponte groups↔ReBAC è il cuore del test (doc 19 §3).
function rebacBind(string $org): void
{
    app()->bind(AdminActorResolver::class, fn (): AdminActorResolver => new class($org) implements AdminActorResolver
    {
        public function __construct(private string $org) {}

        public function resolve(Request $request): ?AdminContext
        {
            $id = $request->headers->get('X-Test-Auth');

            return is_string($id) && $id !== '' ? new AdminContext(new SubjectRef('user', $id), $this->org) : null;
        }
    });
}

/** @param list<string> $permissions */
function rebacGrant(string $subjectId, array $permissions): void
{
    foreach ($permissions as $perm) {
        Grant::create([
            'subject_type' => 'user', 'subject_id' => $subjectId,
            'privilege_type' => 'permission', 'privilege_key' => $perm,
        ]);
    }
}

it('una membership aggiunta via API scrive la tupla `member` che il NativeReBacResolver attraversa', function () {
    $org = Organization::create(['key' => 'acme', 'name' => 'Acme'])->id;
    rebacBind($org);
    rebacGrant('adm', ['iam:groups.manage']);
    $group = Group::create(['organization_id' => $org, 'key' => 'eng', 'name' => 'Engineering']);

    // Aggiungo usr_2 come membro via Admin API: deve materializzare la tupla (user:usr_2 —member→ group:eng).
    $this->postJson("/api/iam/v1/groups/{$group->id}/members", ['member_type' => 'user', 'member_id' => 'usr_2'], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'add'])
        ->assertStatus(201);

    // La tupla ReBAC esiste (single source con la membership).
    expect(Relation::query()->active()
        ->where('subject_type', 'user')->where('subject_id', 'usr_2')
        ->where('relation', 'member')
        ->where('object_type', 'group')->where('object_id', 'eng')
        ->where('organization_id', $org)->exists())->toBeTrue();

    // group:eng editor di doc:99 → per nesting, usr_2 (membro) deve risultare fra i soggetti.
    app(RelationWriter::class)->grant(new SubjectRef('group', 'eng'), 'editor', new ResourceRef('doc', '99'), null, $org);

    $subjects = app(NativeReBacResolver::class)->listSubjects('editor', new ResourceRef('doc', '99'), $org);
    $ids = array_map(static fn (SubjectRef $s): string => $s->id, $subjects);

    expect($ids)->toContain('usr_2');
});

it('rimuovendo la membership via API la tupla `member` viene revocata (resolver non la vede più)', function () {
    $org = Organization::create(['key' => 'acme', 'name' => 'Acme'])->id;
    rebacBind($org);
    rebacGrant('adm', ['iam:groups.manage']);
    $group = Group::create(['organization_id' => $org, 'key' => 'eng', 'name' => 'Engineering']);
    app(RelationWriter::class)->grant(new SubjectRef('group', 'eng'), 'editor', new ResourceRef('doc', '99'), null, $org);

    $this->postJson("/api/iam/v1/groups/{$group->id}/members", ['member_type' => 'user', 'member_id' => 'usr_2'], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'add'])->assertStatus(201);
    $this->deleteJson("/api/iam/v1/groups/{$group->id}/members", ['member_type' => 'user', 'member_id' => 'usr_2'], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'rm'])->assertOk();

    $subjects = app(NativeReBacResolver::class)->listSubjects('editor', new ResourceRef('doc', '99'), $org);
    $ids = array_map(static fn (SubjectRef $s): string => $s->id, $subjects);

    expect($ids)->not->toContain('usr_2');
});
