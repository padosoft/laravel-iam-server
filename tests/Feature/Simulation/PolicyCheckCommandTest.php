<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Iam\Domain\Authorization\Models\Grant;
use Padosoft\Iam\Domain\Authorization\Models\PolicyProbe;

uses(RefreshDatabase::class);

function expectingProbe(string $subjectId, string $permission, bool $expected): PolicyProbe
{
    return PolicyProbe::query()->create([
        'id' => PolicyProbe::newId(),
        'application_key' => 'warehouse',
        'subject_type' => 'user', 'subject_id' => $subjectId,
        'permission' => $permission,
        'current_aal' => 'aal1',
        'expected_allowed' => $expected,
        'source' => PolicyProbe::SOURCE_MANUAL,
        'probe_hash' => PolicyProbe::hashOf(new SubjectRef('user', $subjectId), $permission, null, [], null, 'aal1', 'warehouse'),
    ]);
}

it('esce zero quando il corpus regge', function () {
    Grant::create([
        'subject_type' => 'user', 'subject_id' => 'usr_1',
        'privilege_type' => 'permission', 'privilege_key' => 'warehouse:stock.read',
        'application_key' => 'warehouse',
    ]);
    expectingProbe('usr_1', 'warehouse:stock.read', true);

    $this->artisan('iam:policy:check')->assertExitCode(0);
});

it('esce non-zero e stampa il perché quando una sonda diverge', function () {
    expectingProbe('usr_1', 'warehouse:stock.read', true);

    $this->artisan('iam:policy:check')
        ->expectsOutputToContain('atteso allow, ottenuto deny')
        ->assertExitCode(1);
});

it('un corpus senza aspettative passa ma lo DICE: un gate che passa a vuoto sembra un gate', function () {
    PolicyProbe::query()->create([
        'id' => PolicyProbe::newId(),
        'application_key' => 'warehouse',
        'subject_type' => 'user', 'subject_id' => 'usr_1',
        'permission' => 'warehouse:stock.read',
        'current_aal' => 'aal1',
        'expected_allowed' => null,
        'source' => PolicyProbe::SOURCE_RECORDED,
        'probe_hash' => PolicyProbe::hashOf(new SubjectRef('user', 'usr_1'), 'warehouse:stock.read', null, [], null, 'aal1', 'warehouse'),
    ]);

    $this->artisan('iam:policy:check')
        ->expectsOutputToContain('non sta controllando niente')
        ->assertExitCode(0);
});

it('--json emette il risultato per una pipeline', function () {
    expectingProbe('usr_1', 'warehouse:stock.read', true);

    $this->artisan('iam:policy:check --json')
        ->expectsOutputToContain('"passed": false')
        ->assertExitCode(1);
});
