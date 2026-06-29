<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Padosoft\Iam\Domain\Audit\AuditChainVerifier;
use Padosoft\Iam\Domain\Audit\Models\AuditEvent;
use Padosoft\Iam\Domain\Audit\Pii\AuditRecorder;
use Padosoft\Iam\Domain\Audit\Pii\LegalHoldActive;
use Padosoft\Iam\Domain\Audit\Pii\SubjectEraser;

uses(RefreshDatabase::class);

function recordWithPii(string $subject = 'usr_77', array $pii = ['email' => 'a@b.test'])
{
    return app(AuditRecorder::class)->record(
        ['stream' => 'org_pii', 'event_type' => 'user.updated', 'organization_id' => 'org_pii', 'risk_level' => 'medium'],
        pii: $pii,
        subject: $subject,
    );
}

it('ip_mode=hash registra un hash (non l\'IP in chiaro)', function () {
    config()->set('iam.audit.ip_mode', 'hash');
    config()->set('iam.audit.ip_pepper', 'pepper-test');

    $event = app(AuditRecorder::class)->record(
        ['stream' => 'org_pii', 'event_type' => 'login', 'risk_level' => 'low'],
        ip: '203.0.113.9',
    );

    expect($event->ip_hash)->not->toBeNull()
        ->and($event->ip_hash)->not->toBe('203.0.113.9')
        ->and($event->ip_hash)->toBe(hash_hmac('sha256', '203.0.113.9', 'pepper-test'));
});

it('ip_mode=hash senza pepper in produzione fallisce (no HMAC a chiave vuota)', function () {
    app()->detectEnvironment(fn () => 'production');
    config()->set('iam.audit.ip_mode', 'hash');
    config()->set('iam.audit.ip_pepper', null);

    expect(fn () => app(AuditRecorder::class)->record(
        ['stream' => 'org_pii', 'event_type' => 'login'],
        ip: '203.0.113.9',
    ))->toThrow(RuntimeException::class);
});

it('ip_mode=none non registra alcun IP', function () {
    config()->set('iam.audit.ip_mode', 'none');

    $event = app(AuditRecorder::class)->record(
        ['stream' => 'org_pii', 'event_type' => 'login'],
        ip: '203.0.113.9',
    );

    expect($event->ip_hash)->toBeNull();
});

it('la PII è leggibile finché la DEK del soggetto esiste', function () {
    $event = recordWithPii('usr_77', ['email' => 'a@b.test']);

    expect(app(AuditRecorder::class)->readPii($event))->toBe(['email' => 'a@b.test']);
});

it('il crypto-shredding rende la PII illeggibile MA la catena resta integra', function () {
    $event = recordWithPii('usr_77');
    recordWithPii('usr_77'); // secondo evento nello stesso stream

    app(SubjectEraser::class)->erase('usr_77');

    // PII illeggibile (DEK distrutta), ma la riga e l'hash NON sono cambiati → catena valida.
    expect(app(AuditRecorder::class)->readPii($event->fresh()))->toBeNull()
        ->and(app(AuditChainVerifier::class)->verify('org_pii')->valid)->toBeTrue();
});

it('un legal hold attivo blocca il crypto-shredding (la PII resta leggibile)', function () {
    $event = recordWithPii('usr_88');

    app(SubjectEraser::class)->placeLegalHold('usr_88', 'contenzioso #42');

    expect(fn () => app(SubjectEraser::class)->erase('usr_88'))->toThrow(LegalHoldActive::class);
    expect(app(AuditRecorder::class)->readPii($event->fresh()))->toBe(['email' => 'a@b.test']);
});

it('l\'erasure registra un meta-evento senza PII', function () {
    recordWithPii('usr_99');

    app(SubjectEraser::class)->erase('usr_99');

    $meta = AuditEvent::query()
        ->where('event_type', 'subject.erased')->first();

    expect($meta)->not->toBeNull()
        ->and($meta->pii_encrypted)->toBeNull();
});
