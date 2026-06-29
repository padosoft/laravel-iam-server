<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Iam\Domain\Audit\Models\AuditEvent;
use Padosoft\Iam\Domain\Authorization\Models\Grant;
use Padosoft\Iam\Domain\Authorization\Models\Permission;
use Padosoft\Iam\Domain\Authorization\Models\Relation;
use Padosoft\Iam\Domain\Authorization\Pdp\DecisionQuery;
use Padosoft\Iam\Domain\Authorization\Pdp\NativeReBacResolver;
use Padosoft\Iam\Domain\Authorization\Pdp\NativeSqlEngine;
use Padosoft\Iam\Domain\Authorization\Pdp\ResourceRef;
use Padosoft\Iam\Domain\Authorization\Relations\RelationWriter;
use Padosoft\Iam\Domain\Organizations\Models\Organization;

uses(RefreshDatabase::class);

/** Crea una tupla diretta (bypassa il writer, per setup veloce del grafo). */
function rel(string $subjType, string $subjId, string $relation, string $objType, string $objId, array $opts = []): Relation
{
    return Relation::create(array_merge([
        'subject_type' => $subjType,
        'subject_id' => $subjId,
        'relation' => $relation,
        'object_type' => $objType,
        'object_id' => $objId,
    ], $opts));
}

function resolver(): NativeReBacResolver
{
    return new NativeReBacResolver;
}

function rebacQuery(string $relation, string $objType, string $objId, array $opts = []): DecisionQuery
{
    return new DecisionQuery(
        subject: new SubjectRef('user', $opts['subject'] ?? 'usr_1'),
        permission: $opts['permission'] ?? '',
        organizationId: $opts['org'] ?? null,
        context: $opts['context'] ?? [],
        relation: $relation,
        object: new ResourceRef($objType, $objId),
    );
}

// --- Relazione diretta ---

it('relazione diretta: tupla presente → allow, assente → deny', function () {
    rel('user', 'usr_1', 'editor', 'doc', '42');

    expect(resolver()->hasRelation(new SubjectRef('user', 'usr_1'), 'editor', new ResourceRef('doc', '42'))->holds)->toBeTrue()
        ->and(resolver()->hasRelation(new SubjectRef('user', 'usr_1'), 'editor', new ResourceRef('doc', '99'))->holds)->toBeFalse();
});

it('PDP: check relation-diretta produce allow con matched=relation', function () {
    rel('user', 'usr_1', 'viewer', 'doc', '42');

    $d = (new NativeSqlEngine)->decide(rebacQuery('viewer', 'doc', '42'));

    expect($d->allowed)->toBeTrue()
        ->and($d->matched)->toBe([['type' => 'relation', 'key' => 'viewer']]);
});

// --- Implicazione (userset rewrite) ---

it('rewrite: owner soddisfa editor e viewer, ma viewer NON soddisfa editor', function () {
    rel('user', 'usr_1', 'owner', 'doc', '42');
    rel('user', 'usr_2', 'viewer', 'doc', '42');

    expect(resolver()->hasRelation(new SubjectRef('user', 'usr_1'), 'editor', new ResourceRef('doc', '42'))->holds)->toBeTrue()
        ->and(resolver()->hasRelation(new SubjectRef('user', 'usr_1'), 'viewer', new ResourceRef('doc', '42'))->holds)->toBeTrue()
        ->and(resolver()->hasRelation(new SubjectRef('user', 'usr_2'), 'editor', new ResourceRef('doc', '42'))->holds)->toBeFalse();
});

// --- Nesting gruppi ---

it('nesting gruppi: membro di gruppo con relazione → allow (transitivo)', function () {
    rel('user', 'usr_2', 'member', 'group', 'eng');
    rel('group', 'eng', 'member', 'group', 'all');   // eng ⊂ all
    rel('group', 'all', 'editor', 'doc', '99');

    $r = resolver()->hasRelation(new SubjectRef('user', 'usr_2'), 'editor', new ResourceRef('doc', '99'));

    expect($r->holds)->toBeTrue()
        ->and(implode(' / ', $r->path))->toContain('member');
});

// --- Gerarchia risorse ---

it('gerarchia: owner di una cartella → relazione sul documento figlio', function () {
    rel('user', 'usr_3', 'owner', 'folder', '7');
    rel('doc', '42', 'parent', 'folder', '7');       // doc:42 figlio di folder:7

    expect(resolver()->hasRelation(new SubjectRef('user', 'usr_3'), 'owner', new ResourceRef('doc', '42'))->holds)->toBeTrue();
});

// --- Permission→relation binding ---

it('PDP: permission→relation binding concede il permesso via relazione', function () {
    Permission::create(['app_key' => 'doc', 'key' => 'edit', 'full_key' => 'doc:edit', 'relation' => 'editor']);
    rel('user', 'usr_1', 'editor', 'doc', '42');

    $q = new DecisionQuery(
        subject: new SubjectRef('user', 'usr_1'),
        permission: 'doc:edit',
        object: new ResourceRef('doc', '42'),
    );

    expect((new NativeSqlEngine)->decide($q)->allowed)->toBeTrue();
});

it('PDP: deny esplicito RBAC scavalca il permit relazionale (deny-overrides)', function () {
    Permission::create(['app_key' => 'doc', 'key' => 'edit', 'full_key' => 'doc:edit', 'relation' => 'editor']);
    rel('user', 'usr_1', 'editor', 'doc', '42');
    Grant::create([
        'subject_type' => 'user', 'subject_id' => 'usr_1',
        'privilege_type' => 'permission', 'privilege_key' => 'doc:edit',
        'effect' => 'deny',
    ]);

    $q = new DecisionQuery(
        subject: new SubjectRef('user', 'usr_1'),
        permission: 'doc:edit',
        object: new ResourceRef('doc', '42'),
    );

    expect((new NativeSqlEngine)->decide($q)->allowed)->toBeFalse();
});

// --- Condition ABAC sulla tupla ---

it('condition: tupla con condizione non soddisfatta dal context → deny (fail-closed)', function () {
    rel('user', 'usr_1', 'editor', 'doc', '42', ['condition' => ['amount' => ['<=' => 500]]]);

    expect(resolver()->hasRelation(new SubjectRef('user', 'usr_1'), 'editor', new ResourceRef('doc', '42'), ['amount' => 300])->holds)->toBeTrue()
        ->and(resolver()->hasRelation(new SubjectRef('user', 'usr_1'), 'editor', new ResourceRef('doc', '42'), ['amount' => 900])->holds)->toBeFalse();
});

// --- list-subjects / list-resources ---

it('list-subjects: chi ha la relazione, inclusi i membri del gruppo', function () {
    rel('user', 'usr_2', 'member', 'group', 'eng');
    rel('group', 'eng', 'editor', 'doc', '99');

    $subjects = collect(resolver()->listSubjects('editor', new ResourceRef('doc', '99')))
        ->map(fn (SubjectRef $s) => (string) $s)->all();

    expect($subjects)->toContain('user:usr_2');
});

it('list-resources: su cosa il soggetto ha la relazione, inclusi i figli', function () {
    rel('user', 'usr_3', 'owner', 'folder', '7');
    rel('doc', '42', 'parent', 'folder', '7');

    $resources = collect(resolver()->listResources(new SubjectRef('user', 'usr_3'), 'owner'))
        ->map(fn (array $r) => $r['type'].':'.$r['id'])->all();

    expect($resources)->toContain('folder:7')->toContain('doc:42');
});

// --- Tenant isolation ---

it('tenant isolation: una tupla di un altro org non è attraversabile', function () {
    $a = Organization::create(['key' => 'a', 'name' => 'A']);
    $b = Organization::create(['key' => 'b', 'name' => 'B']);

    // Tupla globale (org null): visibile da qualunque org.
    rel('user', 'usr_1', 'editor', 'doc', '42', ['organization_id' => null]);
    // Tupla scoped su org A: NON visibile interrogando da org B.
    rel('user', 'usr_9', 'editor', 'doc', '77', ['organization_id' => $a->id]);

    expect(resolver()->hasRelation(new SubjectRef('user', 'usr_1'), 'editor', new ResourceRef('doc', '42'), [], $b->id)->holds)->toBeTrue()
        ->and(resolver()->hasRelation(new SubjectRef('user', 'usr_9'), 'editor', new ResourceRef('doc', '77'), [], $a->id)->holds)->toBeTrue()
        ->and(resolver()->hasRelation(new SubjectRef('user', 'usr_9'), 'editor', new ResourceRef('doc', '77'), [], $b->id)->holds)->toBeFalse();
});

// --- Fail-closed: niente object, cicli ---

it('fail-closed: senza object non c\'è permit relazionale', function () {
    Permission::create(['app_key' => 'doc', 'key' => 'edit', 'full_key' => 'doc:edit', 'relation' => 'editor']);
    rel('user', 'usr_1', 'editor', 'doc', '42');

    $q = new DecisionQuery(subject: new SubjectRef('user', 'usr_1'), permission: 'doc:edit'); // object null

    expect((new NativeSqlEngine)->decide($q)->allowed)->toBeFalse();
});

it('cycle-guard: cicli fra gruppi non causano loop infinito e si risolvono', function () {
    rel('user', 'usr_1', 'member', 'group', 'a');
    rel('group', 'a', 'member', 'group', 'b');
    rel('group', 'b', 'member', 'group', 'a');       // ciclo a↔b
    rel('group', 'b', 'editor', 'doc', '42');

    expect(resolver()->hasRelation(new SubjectRef('user', 'usr_1'), 'editor', new ResourceRef('doc', '42'))->holds)->toBeTrue();
});

it('bounded: oltre MAX_DEPTH la gerarchia non propaga (fail-closed)', function () {
    // Catena di parent più lunga di MAX_DEPTH: owner in cima non raggiunge il fondo.
    $depth = NativeReBacResolver::MAX_DEPTH + 2;
    for ($i = 0; $i < $depth; $i++) {
        rel('node', "n{$i}", 'parent', 'node', 'n'.($i + 1));
    }
    rel('user', 'usr_1', 'owner', 'node', "n{$depth}"); // owner della radice (in cima)

    // n0 è a depth+1 salti dalla radice → oltre il cap → deny.
    expect(resolver()->hasRelation(new SubjectRef('user', 'usr_1'), 'owner', new ResourceRef('node', 'n0'))->holds)->toBeFalse();
});

// --- RelationWriter ---

it('writer: un grant ripetuto su tupla già attiva NON ri-emette audit (no-op)', function () {
    $w = new RelationWriter;
    $s = new SubjectRef('user', 'usr_1');
    $o = new ResourceRef('doc', '42');

    $w->grant($s, 'editor', $o);
    $w->grant($s, 'editor', $o); // no-op idempotente
    expect(AuditEvent::query()->where('event_type', 'iam.relation.granted')->count())->toBe(1);

    // Revoca + nuovo grant = riattivazione → nuovo evento granted.
    $w->revoke($s, 'editor', $o);
    $w->grant($s, 'editor', $o);
    expect(AuditEvent::query()->where('event_type', 'iam.relation.granted')->count())->toBe(2);
});

it('list-* sono tenant-scoped: non vedono tuple di un altro org', function () {
    $a = Organization::create(['key' => 'a', 'name' => 'A']);
    $b = Organization::create(['key' => 'b', 'name' => 'B']);
    rel('user', 'usr_1', 'editor', 'doc', '42', ['organization_id' => $a->id]);

    expect(collect(resolver()->listSubjects('editor', new ResourceRef('doc', '42'), $a->id))->map(fn ($s) => (string) $s)->all())->toContain('user:usr_1')
        ->and(resolver()->listSubjects('editor', new ResourceRef('doc', '42'), $b->id))->toBe([]);
});

it('writer: grant è idempotente (no duplicati) e revoke disattiva', function () {
    $w = new RelationWriter;
    $s = new SubjectRef('user', 'usr_1');
    $o = new ResourceRef('doc', '42');

    $w->grant($s, 'editor', $o);
    $w->grant($s, 'editor', $o); // stessa identità → nessun duplicato

    expect(Relation::query()->where('subject_id', 'usr_1')->count())->toBe(1)
        ->and(resolver()->hasRelation($s, 'editor', $o)->holds)->toBeTrue();

    expect($w->revoke($s, 'editor', $o))->toBeTrue()
        ->and(resolver()->hasRelation($s, 'editor', $o)->holds)->toBeFalse();
});
