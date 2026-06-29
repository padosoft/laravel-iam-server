<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Padosoft\Iam\Domain\Audit\AuditChainAppender;
use Padosoft\Iam\Domain\Audit\AuditChainVerifier;

uses(RefreshDatabase::class);

/** @return array<string, mixed> */
function auditAttrs(array $overrides = []): array
{
    return array_merge([
        'stream' => 'org_acme',
        'event_type' => 'grant.assigned',
        'actor_user_id' => 'usr_1',
        'target_type' => 'role',
        'target_id' => 'warehouse:stock_operator',
        'organization_id' => 'org_acme',
        'risk_level' => 'high',
        'after_json' => ['role' => 'stock_operator'],
    ], $overrides);
}

it('sigilla gli eventi in una catena (genesi prev_hash=0, seq progressivo)', function () {
    $appender = app(AuditChainAppender::class);

    $a = $appender->append(auditAttrs());
    $b = $appender->append(auditAttrs(['event_type' => 'grant.revoked']));

    expect($a->seq)->toBe(1)
        ->and($a->prev_hash)->toBe(str_repeat('0', 64))
        ->and($a->hash)->toHaveLength(64)
        ->and($b->seq)->toBe(2)
        ->and($b->prev_hash)->toBe($a->hash)
        ->and($b->hash)->not->toBe($a->hash);
});

it('stream distinti hanno catene indipendenti', function () {
    $appender = app(AuditChainAppender::class);

    $a = $appender->append(auditAttrs(['stream' => 'org_a']));
    $b = $appender->append(auditAttrs(['stream' => 'org_b']));

    expect($a->seq)->toBe(1)
        ->and($b->seq)->toBe(1)
        ->and($b->prev_hash)->toBe(str_repeat('0', 64));
});

it('verifica una catena integra', function () {
    $appender = app(AuditChainAppender::class);
    $appender->append(auditAttrs());
    $appender->append(auditAttrs(['event_type' => 'grant.revoked']));
    $appender->append(auditAttrs(['event_type' => 'token.issued']));

    $result = app(AuditChainVerifier::class)->verify('org_acme');

    expect($result->valid)->toBeTrue()
        ->and($result->firstBrokenUuid)->toBeNull();
});

it('rileva la manomissione di una riga (tamper-evidence)', function () {
    $appender = app(AuditChainAppender::class);
    $a = $appender->append(auditAttrs());
    $appender->append(auditAttrs(['event_type' => 'grant.revoked']));

    // Manomissione diretta sul DB: cambia il contenuto senza ricalcolare l'hash.
    DB::table('iam_audit_events')->where('uuid', $a->uuid)
        ->update(['after_json' => json_encode(['tampered' => true])]);

    $result = app(AuditChainVerifier::class)->verify('org_acme');

    expect($result->valid)->toBeFalse()
        ->and($result->firstBrokenUuid)->toBe($a->uuid);
});

it('rileva un buco nella sequenza (cancellazione di un evento)', function () {
    $appender = app(AuditChainAppender::class);
    $appender->append(auditAttrs());
    $b = $appender->append(auditAttrs(['event_type' => 'grant.revoked']));
    $appender->append(auditAttrs(['event_type' => 'token.issued']));

    DB::table('iam_audit_events')->where('uuid', $b->uuid)->delete();

    $result = app(AuditChainVerifier::class)->verify('org_acme');

    expect($result->valid)->toBeFalse();
});

it('rileva il troncamento di coda (cancellazione degli ultimi eventi)', function () {
    $appender = app(AuditChainAppender::class);
    $appender->append(auditAttrs());
    $appender->append(auditAttrs(['event_type' => 'grant.revoked']));
    $last = $appender->append(auditAttrs(['event_type' => 'token.issued']));

    // Cancella solo l'ULTIMO evento: il prefisso resta valido ma la testa punta alla coda rimossa.
    DB::table('iam_audit_events')->where('uuid', $last->uuid)->delete();

    $result = app(AuditChainVerifier::class)->verify('org_acme');

    expect($result->valid)->toBeFalse();
});

it('rileva la cancellazione della testa dello stream (fail-closed)', function () {
    $appender = app(AuditChainAppender::class);
    $appender->append(auditAttrs());
    $appender->append(auditAttrs(['event_type' => 'grant.revoked']));

    // Un attaccante cancella la riga head sperando che la verifica salti il controllo di coda.
    DB::table('iam_audit_heads')->where('stream', 'org_acme')->delete();

    $result = app(AuditChainVerifier::class)->verify('org_acme');

    expect($result->valid)->toBeFalse()
        ->and($result->cause)->toBe('head_missing');
});

it('il comando iam:audit:verify segnala OK su catena integra e FAILURE su manomissione', function () {
    $appender = app(AuditChainAppender::class);
    $a = $appender->append(auditAttrs());
    $appender->append(auditAttrs(['event_type' => 'grant.revoked']));

    $this->artisan('iam:audit:verify', ['--stream' => 'org_acme'])->assertSuccessful();

    DB::table('iam_audit_events')->where('uuid', $a->uuid)
        ->update(['after_json' => json_encode(['tampered' => true])]);

    $this->artisan('iam:audit:verify', ['--stream' => 'org_acme'])->assertFailed();
});
