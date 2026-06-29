<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Padosoft\Iam\Domain\Audit\AuditChainAppender;
use Padosoft\Iam\Domain\Audit\Export\AuditExporter;
use Padosoft\Iam\Domain\Audit\Export\CefFormatter;
use Padosoft\Iam\Domain\Audit\Export\LeefFormatter;
use Padosoft\Iam\Domain\Audit\Export\OcsfMapper;

uses(RefreshDatabase::class);

function exportEvent(string $type = 'grant.assigned', string $risk = 'high')
{
    return app(AuditChainAppender::class)->append([
        'stream' => 'org_exp',
        'event_type' => $type,
        'actor_user_id' => 'usr_42',
        'target_type' => 'role',
        'target_id' => 'warehouse:stock_operator',
        'organization_id' => 'org_exp',
        'risk_level' => $risk,
    ]);
}

it('OcsfMapper normalizza un evento nello schema OCSF', function () {
    $event = exportEvent('grant.assigned', 'high');

    $ocsf = app(OcsfMapper::class)->map($event);

    expect($ocsf['category_uid'])->toBe(3)
        ->and($ocsf['severity_id'])->toBe(4) // high
        ->and($ocsf['actor']['user']['uid'])->toBe('usr_42')
        ->and($ocsf['metadata']['product']['name'])->toBe('Laravel IAM')
        ->and($ocsf['unmapped']['iam_event_type'])->toBe('grant.assigned')
        ->and($ocsf['unmapped']['iam_hash'])->toBe($event->hash);
});

it('OcsfMapper mappa il risk_level su severity_id', function () {
    expect(app(OcsfMapper::class)->map(exportEvent('e', 'low'))['severity_id'])->toBe(2)
        ->and(app(OcsfMapper::class)->map(exportEvent('e', 'critical'))['severity_id'])->toBe(5);
});

it('CefFormatter produce una riga CEF valida con header e estensioni', function () {
    $line = app(CefFormatter::class)->format(exportEvent('grant.assigned', 'high'));

    expect($line)->toStartWith('CEF:0|Padosoft|Laravel IAM|')
        ->and($line)->toContain('|grant.assigned|')
        ->and($line)->toContain('suser=usr_42'); // l'attore è la sorgente, non la destinazione
});

it('CefFormatter fa escape dei caratteri speciali (pipe/backslash) nell\'header', function () {
    $line = app(CefFormatter::class)->format(exportEvent('weird|type', 'high'));

    expect($line)->toContain('weird\\|type'); // pipe escapata nel name
});

it('LeefFormatter produce una riga LEEF valida', function () {
    $line = app(LeefFormatter::class)->format(exportEvent('grant.assigned', 'high'));

    expect($line)->toStartWith('LEEF:2.0|Padosoft|Laravel IAM|')
        ->and($line)->toContain('|x09|')               // 6° campo header = delimitatore (LEEF 2.0)
        ->and($line)->toContain('cat=grant.assigned')
        ->and($line)->toContain('devTimeFormat=');     // evita ambiguità epoch su QRadar
});

it('AuditExporter esporta gli eventi di uno stream nel formato richiesto', function () {
    exportEvent('grant.assigned');
    exportEvent('grant.revoked');

    $ocsf = iterator_to_array(app(AuditExporter::class)->export('org_exp', format: 'ocsf'));
    $cef = iterator_to_array(app(AuditExporter::class)->export('org_exp', format: 'cef'));

    expect($ocsf)->toHaveCount(2)
        ->and($ocsf[0])->toBeArray()
        ->and($cef)->toHaveCount(2)
        ->and($cef[0])->toBeString();
});

it('il comando iam:audit:export emette le righe degli eventi', function () {
    exportEvent('grant.assigned');

    $this->artisan('iam:audit:export', ['--stream' => 'org_exp', '--format' => 'cef'])
        ->expectsOutputToContain('CEF:0|Padosoft|Laravel IAM|')
        ->assertSuccessful();
});
