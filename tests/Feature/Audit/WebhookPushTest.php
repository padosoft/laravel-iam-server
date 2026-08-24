<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Schema;
use Padosoft\Iam\Contracts\Crypto\SecretCipher;
use Padosoft\Iam\Domain\Audit\Outbox\Outbox;
use Padosoft\Iam\Domain\Audit\Outbox\OutboxProcessor;
use Padosoft\Iam\Domain\Audit\Pii\AuditRecorder;
use Padosoft\Iam\Domain\Audit\Webhooks\Models\WebhookDelivery;
use Padosoft\Iam\Domain\Audit\Webhooks\Models\WebhookSubscription;

uses(RefreshDatabase::class);

// P2: il push webhook al momento della sigillatura — il call site che collega la hash-chain al
// WebhookDispatcher (prima esisteva solo il dispatcher, mai chiamato in produzione).

function pushSubscribe(string $url, array $filters, ?string $org = 'org_push'): WebhookSubscription
{
    $sub = new WebhookSubscription;
    $sub->fill([
        'organization_id' => $org,
        'url' => $url,
        'secret_encrypted' => app(SecretCipher::class)->encrypt('whsec_push'),
        'event_filters' => $filters,
    ]);
    $sub->save();

    return $sub;
}

it('un evento registrato dal recorder viene spinto alle subscription che matchano', function () {
    Http::fake(['https://hook.test/*' => Http::response('', 200)]);
    pushSubscribe('https://hook.test/in', ['delegation.*']);

    app(AuditRecorder::class)->record([
        'stream' => 'delegation',
        'event_type' => 'delegation.grant.revoked',
        'organization_id' => 'org_push',
        'metadata_json' => ['grant_id' => 'dgr_1'],
    ]);

    Http::assertSentCount(1);
    expect(WebhookDelivery::query()->where('status', 'delivered')->count())->toBe(1);
});

it('il push è gated su iam.audit.webhooks.push_enabled', function () {
    config()->set('iam.audit.webhooks.push_enabled', false);
    Http::fake();
    pushSubscribe('https://hook.test/in', ['*']);

    app(AuditRecorder::class)->record([
        'stream' => 'delegation',
        'event_type' => 'delegation.grant.revoked',
        'organization_id' => 'org_push',
    ]);

    Http::assertNothingSent();
    expect(WebhookDelivery::query()->count())->toBe(0);
});

it('un fallimento del push non fa mai fallire la registrazione dell\'evento (best-effort)', function () {
    // Il caso reale piu' probabile: un host con migrazioni webhook non pubblicate. La query delle
    // subscription lancia -> il pusher assorbe e report()-a; l'evento resta sigillato in catena.
    Schema::drop('iam_webhook_deliveries');
    Schema::drop('iam_webhook_subscriptions');

    $event = app(AuditRecorder::class)->record([
        'stream' => 'delegation',
        'event_type' => 'delegation.grant.revoked',
        'organization_id' => 'org_push',
    ]);

    expect($event->uuid)->not->toBeNull()
        ->and($event->hash)->not->toBeNull();
});

it('un evento sigillato via outbox viene spinto dopo il commit', function () {
    Http::fake(['https://hook.test/*' => Http::response('', 200)]);
    pushSubscribe('https://hook.test/in', ['session.*']);

    app(Outbox::class)->publish([
        'stream' => 'org_push',
        'event_type' => 'session.revoked',
        'organization_id' => 'org_push',
    ]);
    $delivered = app(OutboxProcessor::class)->process();

    expect($delivered)->toBe(1);
    Http::assertSentCount(1);
    expect(WebhookDelivery::query()->where('status', 'delivered')->count())->toBe(1);
});

it('iam:webhooks-retry riconsegna le delivery scadute', function () {
    Http::fakeSequence('https://hook.test/*')->push('boom', 500)->push('', 200);
    pushSubscribe('https://hook.test/in', ['*']);

    app(AuditRecorder::class)->record([
        'stream' => 'delegation',
        'event_type' => 'delegation.exchange.denied',
        'organization_id' => 'org_push',
    ]);
    expect(WebhookDelivery::query()->value('status'))->toBe('retrying');

    WebhookDelivery::query()->update(['next_retry_at' => now()->subMinute()]);
    $this->artisan('iam:webhooks-retry')->assertExitCode(0);

    expect(WebhookDelivery::query()->value('status'))->toBe('delivered');
});
