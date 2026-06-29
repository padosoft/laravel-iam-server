<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Iam\Domain\Authorization\Models\Grant;
use Padosoft\Iam\Domain\Authorization\Pdp\DecisionQuery;
use Padosoft\Iam\Domain\Authorization\Pdp\NativeSqlEngine;
use Padosoft\Iam\Domain\Governance\GrantUsageRecorder;

uses(RefreshDatabase::class);

function usageGrant(array $overrides = []): Grant
{
    return Grant::create(array_merge([
        'subject_type' => 'user', 'subject_id' => 'usr_u',
        'privilege_type' => 'permission', 'privilege_key' => 'warehouse:stock.read',
        'application_key' => 'warehouse',
    ], $overrides));
}

function decideRead(string $subject = 'usr_u'): void
{
    app(NativeSqlEngine::class)->decide(new DecisionQuery(
        subject: new SubjectRef('user', $subject),
        permission: 'warehouse:stock.read',
        applicationKey: 'warehouse',
    ));
}

it('il PDP registra last_used_at sul grant che produce un allow (dopo flush)', function () {
    $grant = usageGrant();
    expect($grant->last_used_at)->toBeNull();

    decideRead();
    app(GrantUsageRecorder::class)->flush();

    expect($grant->fresh()->last_used_at)->not->toBeNull();
});

it('un deny/default-deny non registra alcun uso', function () {
    $grant = usageGrant();

    decideRead('nessuno'); // soggetto senza grant → default-deny
    app(GrantUsageRecorder::class)->flush();

    expect($grant->fresh()->last_used_at)->toBeNull();
});

it('il recorder è batched: più decisioni → un solo flush aggiorna tutti i grant usati', function () {
    $g1 = usageGrant(['subject_id' => 'usr_a']);
    $g2 = usageGrant(['subject_id' => 'usr_b']);

    decideRead('usr_a');
    decideRead('usr_b');
    app(GrantUsageRecorder::class)->flush();

    expect($g1->fresh()->last_used_at)->not->toBeNull()
        ->and($g2->fresh()->last_used_at)->not->toBeNull();
});

it('lo stesso grant usato più volte nella stessa richiesta è deduplicato (un solo UPDATE)', function () {
    $grant = usageGrant();

    decideRead();
    decideRead();
    decideRead();

    // Una sola scrittura batch deve toccare il grant: nessun accumulo nel buffer.
    DB::enableQueryLog();
    app(GrantUsageRecorder::class)->flush();
    $updates = collect(DB::getQueryLog())->filter(fn ($q) => str_contains($q['query'], 'update'));

    expect($updates)->toHaveCount(1)
        ->and($grant->fresh()->last_used_at)->not->toBeNull();
});

it('last_used_at NON è fillable (si imposta solo via usage capture controllato)', function () {
    $grant = usageGrant(['last_used_at' => now()->subYear()]);

    // Il valore passato a create() viene ignorato (fuori da fillable).
    expect($grant->fresh()->last_used_at)->toBeNull();
});
