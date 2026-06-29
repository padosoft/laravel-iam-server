<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Padosoft\Iam\Domain\Audit\AuditChainAppender;
use Padosoft\Iam\Domain\Audit\AuditCheckpointer;
use Padosoft\Iam\Domain\Audit\Models\AuditCheckpoint;

uses(RefreshDatabase::class);

/** @return array<string, mixed> */
function cpAttrs(array $overrides = []): array
{
    return array_merge([
        'stream' => 'org_cp',
        'event_type' => 'grant.assigned',
        'risk_level' => 'high',
    ], $overrides);
}

it('crea un checkpoint firmato sulla testa corrente dello stream', function () {
    $appender = app(AuditChainAppender::class);
    $appender->append(cpAttrs());
    $last = $appender->append(cpAttrs(['event_type' => 'grant.revoked']));

    $cp = app(AuditCheckpointer::class)->checkpoint('org_cp');

    expect($cp)->not->toBeNull()
        ->and($cp->up_to_seq)->toBe(2)
        ->and($cp->head_hash)->toBe($last->hash)
        ->and($cp->signature)->toBeString()->not->toBe('');
});

it('non crea un checkpoint per uno stream senza eventi', function () {
    expect(app(AuditCheckpointer::class)->checkpoint('vuoto'))->toBeNull();
});

it('verifica un checkpoint integro', function () {
    $appender = app(AuditChainAppender::class);
    $appender->append(cpAttrs());
    $cp = app(AuditCheckpointer::class)->checkpoint('org_cp');

    expect(app(AuditCheckpointer::class)->verify($cp)->valid)->toBeTrue();
});

it('rileva un checkpoint con head_hash manomesso (firma non combacia)', function () {
    $appender = app(AuditChainAppender::class);
    $appender->append(cpAttrs());
    $cp = app(AuditCheckpointer::class)->checkpoint('org_cp');

    DB::table('iam_audit_checkpoints')->where('id', $cp->id)
        ->update(['head_hash' => str_repeat('a', 64)]);

    $reloaded = AuditCheckpoint::query()->findOrFail($cp->id);
    expect(app(AuditCheckpointer::class)->verify($reloaded)->valid)->toBeFalse();
});

it('rileva un checkpoint con up_to_seq manomesso', function () {
    $appender = app(AuditChainAppender::class);
    $appender->append(cpAttrs());
    $cp = app(AuditCheckpointer::class)->checkpoint('org_cp');

    DB::table('iam_audit_checkpoints')->where('id', $cp->id)->update(['up_to_seq' => 999]);

    $reloaded = AuditCheckpoint::query()->findOrFail($cp->id);
    $result = app(AuditCheckpointer::class)->verify($reloaded);
    expect($result->valid)->toBeFalse()
        ->and($result->cause)->toBe('tampered');
});

it('rileva una firma valida ma di un altro checkpoint (claim non combaciano)', function () {
    $appender = app(AuditChainAppender::class);
    $appender->append(cpAttrs(['stream' => 'org_x']));
    $appender->append(cpAttrs(['stream' => 'org_y', 'event_type' => 'grant.revoked']));
    $cpX = app(AuditCheckpointer::class)->checkpoint('org_x');
    $cpY = app(AuditCheckpointer::class)->checkpoint('org_y');

    // Sostituisci la firma di X con quella (valida ma di un altro stream) di Y.
    DB::table('iam_audit_checkpoints')->where('id', $cpX->id)->update(['signature' => $cpY->signature]);

    $reloaded = AuditCheckpoint::query()->findOrFail($cpX->id);
    expect(app(AuditCheckpointer::class)->verify($reloaded)->valid)->toBeFalse();
});

it('il comando iam:audit:checkpoint crea un checkpoint', function () {
    $appender = app(AuditChainAppender::class);
    $appender->append(cpAttrs());

    $this->artisan('iam:audit:checkpoint', ['--stream' => 'org_cp'])->assertSuccessful();

    expect(AuditCheckpoint::query()->where('stream', 'org_cp')->exists())->toBeTrue();
});
