<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Padosoft\Iam\Domain\Audit\AuditChainVerifier;
use Padosoft\Iam\Domain\Audit\Events\EventsQuery;
use Padosoft\Iam\Domain\Audit\Models\AuditEvent;
use Padosoft\Iam\Domain\Audit\Outbox\Outbox;
use Padosoft\Iam\Domain\Audit\Outbox\OutboxMessage;
use Padosoft\Iam\Domain\Audit\Outbox\OutboxProcessor;

uses(RefreshDatabase::class);

/** @return array<string, mixed> */
function obAttrs(array $overrides = []): array
{
    return array_merge([
        'stream' => 'org_ob',
        'event_type' => 'grant.assigned',
        'actor_user_id' => 'usr_1',
        'risk_level' => 'high',
        'after_json' => ['role' => 'op'],
    ], $overrides);
}

it('publish scrive un messaggio pending nell\'outbox (non ancora sigillato)', function () {
    $msg = app(Outbox::class)->publish(obAttrs());

    expect($msg->status)->toBe('pending')
        ->and(AuditEvent::query()->count())->toBe(0);
});

it('il processor sigilla i pending nella hash-chain e li marca delivered', function () {
    $outbox = app(Outbox::class);
    $outbox->publish(obAttrs());
    $outbox->publish(obAttrs(['event_type' => 'grant.revoked']));

    $processed = app(OutboxProcessor::class)->process();

    expect($processed)->toBe(2)
        ->and(AuditEvent::query()->count())->toBe(2)
        ->and(OutboxMessage::query()->where('status', 'delivered')->count())->toBe(2)
        ->and(app(AuditChainVerifier::class)->verify('org_ob')->valid)->toBeTrue();
});

it('il processor è idempotente: ri-processare non duplica eventi di audit', function () {
    app(Outbox::class)->publish(obAttrs());

    app(OutboxProcessor::class)->process();
    app(OutboxProcessor::class)->process(); // seconda passata

    expect(AuditEvent::query()->count())->toBe(1);
});

it('un poison message va in DLQ (failed) dopo la soglia di tentativi, non in loop infinito', function () {
    config()->set('iam.audit.outbox_max_attempts', 2);

    // Inseriamo direttamente un messaggio con payload invalido (senza stream) → l'appender lancia.
    $msg = new OutboxMessage;
    $msg->forceFill([
        'event_type' => 'broken',
        'stream' => 'org_ob',
        'payload_json' => ['event_type' => 'broken'], // manca "stream" → append() rifiuta
        'status' => 'pending',
        'attempts' => 0,
        'created_at' => now(),
    ])->save();

    app(OutboxProcessor::class)->process(); // attempt 1 → resta pending
    expect(OutboxMessage::query()->findOrFail($msg->id)->status)->toBe('pending');

    app(OutboxProcessor::class)->process(); // attempt 2 → soglia → failed

    $reloaded = OutboxMessage::query()->findOrFail($msg->id);
    expect($reloaded->status)->toBe('failed')
        ->and($reloaded->attempts)->toBe(2)
        ->and($reloaded->last_error)->not->toBeNull()
        ->and(AuditEvent::query()->count())->toBe(0);
});

it('EventsQuery pagina gli eventi sigillati con cursore stabile basato su seq', function () {
    $outbox = app(Outbox::class);
    foreach (range(1, 5) as $i) {
        $outbox->publish(obAttrs(['event_type' => "evt.{$i}"]));
    }
    app(OutboxProcessor::class)->process();

    $query = app(EventsQuery::class);
    $page1 = $query->page('org_ob', limit: 2);
    $page2 = $query->page('org_ob', limit: 2, cursor: $page1->nextCursor);
    $page3 = $query->page('org_ob', limit: 2, cursor: $page2->nextCursor);

    $seqs = array_merge(
        array_map(fn (AuditEvent $e): int => $e->seq, $page1->events),
        array_map(fn (AuditEvent $e): int => $e->seq, $page2->events),
        array_map(fn (AuditEvent $e): int => $e->seq, $page3->events),
    );

    expect($seqs)->toBe([1, 2, 3, 4, 5])
        ->and($page3->nextCursor)->toBeNull();
});

it('EventsQuery filtra per prefisso di tipo (es. grant.*)', function () {
    $outbox = app(Outbox::class);
    $outbox->publish(obAttrs(['event_type' => 'grant.assigned']));
    $outbox->publish(obAttrs(['event_type' => 'token.issued']));
    $outbox->publish(obAttrs(['event_type' => 'grant.revoked']));
    app(OutboxProcessor::class)->process();

    $page = app(EventsQuery::class)->page('org_ob', limit: 50, typePrefix: 'grant.');

    $types = array_map(fn (AuditEvent $e): string => $e->event_type, $page->events);
    expect($types)->toEqualCanonicalizing(['grant.assigned', 'grant.revoked']);
});
