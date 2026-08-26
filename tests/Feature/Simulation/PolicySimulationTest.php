<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Iam\Domain\Authorization\Models\Grant;
use Padosoft\Iam\Domain\Authorization\Models\PolicyProbe;
use Padosoft\Iam\Domain\Authorization\Pdp\DecisionQuery;
use Padosoft\Iam\Domain\Authorization\Pdp\NativeSqlEngine;
use Padosoft\Iam\Domain\Authorization\Simulation\BlastRadiusSimulator;
use Padosoft\Iam\Domain\Authorization\Simulation\PolicyProbeRecorder;
use Padosoft\Iam\Domain\Authorization\Simulation\PolicyRegressionRunner;
use Padosoft\Iam\Domain\Authorization\Simulation\ProbeOutcome;

uses(RefreshDatabase::class);

/**
 * Blast radius e regressione.
 *
 * Il test che conta più di tutti è quello sul rollback: il simulatore applica
 * davvero il cambiamento per misurarlo, e se un giorno smettesse di annullarlo
 * "misurare" diventerebbe "applicare" — in un endpoint che un revisore chiama
 * proprio perché NON vuole ancora applicare.
 */
function probe(string $permission, array $opts = []): PolicyProbe
{
    $subject = new SubjectRef($opts['subject_type'] ?? 'user', $opts['subject'] ?? 'usr_1');
    $resource = $opts['resource'] ?? null;
    $context = $opts['context'] ?? [];

    $app = $opts['app'] ?? 'warehouse';

    return PolicyProbe::query()->create([
        'id' => PolicyProbe::newId(),
        'organization_id' => $opts['org'] ?? null,
        'application_key' => $app,
        'subject_type' => $subject->type,
        'subject_id' => $subject->id,
        'permission' => $permission,
        'resource_ref' => $resource,
        'context' => $context !== [] ? $context : null,
        'current_aal' => $opts['aal'] ?? 'aal1',
        'expected_allowed' => $opts['expected'] ?? null,
        'source' => $opts['source'] ?? PolicyProbe::SOURCE_MANUAL,
        'label' => $opts['label'] ?? null,
        'probe_hash' => PolicyProbe::hashOf($subject, $permission, $resource, $context, $opts['org'] ?? null, $opts['aal'] ?? 'aal1', $app),
    ]);
}

function simulator(): BlastRadiusSimulator
{
    return new BlastRadiusSimulator(new NativeSqlEngine);
}

function grantTo(string $subjectId, string $fullKey, string $effect = 'permit'): Grant
{
    return Grant::create([
        'subject_type' => 'user',
        'subject_id' => $subjectId,
        'privilege_type' => 'permission',
        'privilege_key' => $fullKey,
        'application_key' => 'warehouse',
        'effect' => $effect,
    ]);
}

it('vede una decisione passare da deny ad allow, e la chiama granted', function () {
    $p = probe('warehouse:stock.read');

    $report = simulator()->simulate([$p], fn () => grantTo('usr_1', 'warehouse:stock.read'));

    expect($report->counts()[ProbeOutcome::GRANTED])->toBe(1)
        ->and($report->changed()[0]->before)->toBeFalse()
        ->and($report->changed()[0]->after)->toBeTrue();
});

it('vede una decisione passare da allow a deny, e la chiama revoked', function () {
    // Direzione opposta: rompe le persone, non la sicurezza. È un incidente
    // diverso e il report lo tiene separato invece di contare "1 cambiamento".
    grantTo('usr_1', 'warehouse:stock.read');
    $p = probe('warehouse:stock.read');

    $report = simulator()->simulate([$p], fn () => grantTo('usr_1', 'warehouse:stock.read', 'deny'));

    expect($report->counts()[ProbeOutcome::REVOKED])->toBe(1);
});

it('NON committa il cambiamento: misurare non è applicare', function () {
    // Il test portante. Se questo si rompe, un endpoint che un revisore chiama
    // per NON applicare ancora ha appena applicato.
    $p = probe('warehouse:stock.read');

    simulator()->simulate([$p], fn () => grantTo('usr_1', 'warehouse:stock.read'));

    expect(Grant::query()->count())->toBe(0)
        ->and((new NativeSqlEngine)->decide($p->toQuery())->allowed)->toBeFalse();
});

it('un errore VERO del cambiamento risale invece di leggersi come "nessun impatto"', function () {
    $p = probe('warehouse:stock.read');

    expect(fn () => simulator()->simulate([$p], function (): void {
        throw new RuntimeException('il manifest è rotto');
    }))->toThrow(RuntimeException::class, 'il manifest è rotto');

    expect(Grant::query()->count())->toBe(0);
});

it('dentro una transazione del chiamante annulla SOLO la propria parte', function () {
    // Savepoint, non rollback totale: il lavoro di chi ci ha chiamato resta.
    DB::beginTransaction();
    grantTo('usr_2', 'warehouse:stock.read');

    $p = probe('warehouse:stock.read');
    simulator()->simulate([$p], fn () => grantTo('usr_1', 'warehouse:stock.read'));

    expect(Grant::query()->where('subject_id', 'usr_2')->count())->toBe(1)
        ->and(Grant::query()->where('subject_id', 'usr_1')->count())->toBe(0);

    DB::rollBack();
});

it('una sonda invariata non finisce fra i cambiamenti, ma resta nel conteggio', function () {
    $touched = probe('warehouse:stock.read');
    $untouched = probe('warehouse:stock.write', ['subject' => 'usr_9']);

    $report = simulator()->simulate([$touched, $untouched], fn () => grantTo('usr_1', 'warehouse:stock.read'));

    expect($report->outcomes)->toHaveCount(2)
        ->and($report->changed())->toHaveCount(1)
        ->and($report->counts()[ProbeOutcome::UNCHANGED])->toBe(1)
        ->and($report->toArray()['changes'])->toHaveCount(1)
        ->and($report->toArray(includeUnchanged: true)['changes'])->toHaveCount(2);
});

it('il report dichiara che misura solo le sonde che ha', function () {
    // "0 cambiamenti" letto come "nessun rischio" è il modo in cui questa feature
    // farebbe più danni che bene.
    $report = simulator()->simulate([probe('warehouse:stock.read')], fn () => null);

    expect($report->toArray()['coverage']['note'])->toContain('not that nothing does');
});

it('la regressione fallisce quando la policy smette di dire ciò che avevamo deciso', function () {
    grantTo('usr_1', 'warehouse:stock.read');
    probe('warehouse:stock.read', ['expected' => true, 'label' => 'lo stock lo legge sempre']);

    $runner = new PolicyRegressionRunner(new NativeSqlEngine);

    expect($runner->run([...PolicyProbe::query()->get()])->passed())->toBeTrue();

    grantTo('usr_1', 'warehouse:stock.read', 'deny');

    $result = $runner->run([...PolicyProbe::query()->get()]);

    expect($result->passed())->toBeFalse()
        ->and($result->failures[0]['expected_allowed'])->toBeTrue()
        ->and($result->failures[0]['actual_allowed'])->toBeFalse()
        ->and($result->failures[0]['explanation'])->not->toBeEmpty();
});

it('una sonda SENZA esito atteso è ignorata, non inventata', function () {
    // Promuoverla al comportamento corrente trasformerebbe ogni bug esistente in
    // un requisito.
    probe('warehouse:stock.read');

    $result = (new PolicyRegressionRunner(new NativeSqlEngine))->run([...PolicyProbe::query()->get()]);

    expect($result->checked)->toBe(0)
        ->and($result->skipped)->toBe(1)
        ->and($result->passed())->toBeTrue();
});

it('il recorder è spento a rate zero', function () {
    (new PolicyProbeRecorder(sampleRate: 0.0))->record(new DecisionQuery(
        subject: new SubjectRef('user', 'usr_1'),
        permission: 'warehouse:stock.read',
    ));

    expect(PolicyProbe::query()->count())->toBe(0);
});

it('il recorder registra la DOMANDA e mai la risposta, e deduplica', function () {
    $recorder = new PolicyProbeRecorder(sampleRate: 1.0);
    $query = new DecisionQuery(subject: new SubjectRef('user', 'usr_1'), permission: 'warehouse:stock.read');

    $recorder->record($query);
    $recorder->record($query);

    $probes = PolicyProbe::query()->get();

    expect($probes)->toHaveCount(1)
        ->and($probes[0]->expected_allowed)->toBeNull()
        ->and($probes[0]->source)->toBe(PolicyProbe::SOURCE_RECORDED)
        ->and($probes[0]->last_seen_at)->not->toBeNull();
});

it('il recorder si ferma al tetto invece di crescere per sempre', function () {
    $recorder = new PolicyProbeRecorder(sampleRate: 1.0, maxProbes: 2);

    foreach (['a', 'b', 'c', 'd'] as $id) {
        $recorder->record(new DecisionQuery(subject: new SubjectRef('user', $id), permission: 'warehouse:stock.read'));
    }

    expect(PolicyProbe::query()->count())->toBe(2);
});

it('il campionamento è deterministico: la stessa tupla entra sempre o mai', function () {
    // Casuale, la stessa CI vedrebbe corpus diversi a ogni esecuzione.
    $recorder = new PolicyProbeRecorder(sampleRate: 0.5);
    $decisions = [];

    foreach (range(1, 40) as $i) {
        $q = new DecisionQuery(subject: new SubjectRef('user', 'usr_'.$i), permission: 'warehouse:stock.read');
        $recorder->record($q);
        $decisions[$i] = PolicyProbe::query()->count();
    }

    $sampled = PolicyProbe::query()->count();

    // Ri-registrare le stesse tuple non ne aggiunge nessuna nuova.
    foreach (range(1, 40) as $i) {
        $recorder->record(new DecisionQuery(subject: new SubjectRef('user', 'usr_'.$i), permission: 'warehouse:stock.read'));
    }

    expect(PolicyProbe::query()->count())->toBe($sampled)
        ->and($sampled)->toBeGreaterThan(0)
        ->and($sampled)->toBeLessThan(40);
});

it('il digest ignora l\'ordine delle chiavi di contesto', function () {
    $subject = new SubjectRef('user', 'usr_1');

    expect(PolicyProbe::hashOf($subject, 'p', null, ['b' => 2, 'a' => 1]))
        ->toBe(PolicyProbe::hashOf($subject, 'p', null, ['a' => 1, 'b' => 2]));
});
