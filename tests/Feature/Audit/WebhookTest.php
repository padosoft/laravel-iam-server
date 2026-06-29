<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Http;
use Padosoft\Iam\Contracts\Crypto\SecretCipher;
use Padosoft\Iam\Domain\Audit\AuditChainAppender;
use Padosoft\Iam\Domain\Audit\Webhooks\Models\WebhookDelivery;
use Padosoft\Iam\Domain\Audit\Webhooks\Models\WebhookSubscription;
use Padosoft\Iam\Domain\Audit\Webhooks\WebhookDispatcher;
use Padosoft\Iam\Domain\Audit\Webhooks\WebhookRetrier;

uses(RefreshDatabase::class);

function subscribe(string $url, array $filters, string $secret = 'whsec_test'): WebhookSubscription
{
    $sub = new WebhookSubscription;
    $sub->fill([
        'organization_id' => 'org_wh',
        'url' => $url,
        'secret_encrypted' => app(SecretCipher::class)->encrypt($secret),
        'event_filters' => $filters,
    ]);
    $sub->save();

    return $sub;
}

function sealEvent(string $type = 'grant.assigned')
{
    return app(AuditChainAppender::class)->append([
        'stream' => 'org_wh',
        'event_type' => $type,
        'organization_id' => 'org_wh',
        'risk_level' => 'high',
        'after_json' => ['x' => 1],
    ]);
}

it('consegna un POST firmato HMAC alla subscription che matcha il filtro', function () {
    Http::fake(['https://hook.test/*' => Http::response('', 200)]);
    subscribe('https://hook.test/in', ['grant.*']);
    $event = sealEvent('grant.assigned');

    app(WebhookDispatcher::class)->dispatch($event);

    Http::assertSent(function ($request) use ($event) {
        $ts = $request->header('X-IAM-Timestamp')[0] ?? '';
        $sig = $request->header('X-IAM-Signature')[0] ?? '';
        $expected = 't='.$ts.',v1='.hash_hmac('sha256', $ts.'.'.$request->body(), 'whsec_test');

        return $request->url() === 'https://hook.test/in'
            && ($request->header('X-IAM-Event-Id')[0] ?? '') === $event->uuid
            && $sig === $expected;
    });

    expect(WebhookDelivery::query()->where('status', 'delivered')->count())->toBe(1);
});

it('non consegna a una subscription il cui filtro non matcha', function () {
    Http::fake(['https://hook.test/*' => Http::response('', 200)]);
    subscribe('https://hook.test/in', ['billing.*']);

    app(WebhookDispatcher::class)->dispatch(sealEvent('grant.assigned'));

    Http::assertNothingSent();
    expect(WebhookDelivery::query()->count())->toBe(0);
});

it('una consegna fallita (5xx) viene marcata retrying con next_retry_at', function () {
    Http::fake(['https://hook.test/*' => Http::response('boom', 500)]);
    subscribe('https://hook.test/in', ['*']);

    app(WebhookDispatcher::class)->dispatch(sealEvent());

    $d = WebhookDelivery::query()->firstOrFail();
    expect($d->status)->toBe('retrying')
        ->and($d->response_code)->toBe(500)
        ->and($d->next_retry_at)->not->toBeNull();
});

it('il retrier riconsegna le delivery scadute e segna delivered al successo', function () {
    // Sequenza: 1ª richiesta (dispatch) 500, 2ª (retry) 200.
    Http::fakeSequence('https://hook.test/*')->push('boom', 500)->push('', 200);
    subscribe('https://hook.test/in', ['*']);
    app(WebhookDispatcher::class)->dispatch(sealEvent());

    // Forziamo la scadenza del retry.
    WebhookDelivery::query()->update(['next_retry_at' => now()->subMinute()]);

    $retried = app(WebhookRetrier::class)->retryDue();

    expect($retried)->toBe(1)
        ->and(WebhookDelivery::query()->where('status', 'delivered')->count())->toBe(1);
});

it('blocca un URL SSRF (IP metadata/link-local) senza inviare e marca failed', function () {
    Http::fake(['*' => Http::response('', 200)]);
    subscribe('http://169.254.169.254/latest/meta-data', ['*']);

    app(WebhookDispatcher::class)->dispatch(sealEvent());

    Http::assertNothingSent();
    $d = WebhookDelivery::query()->firstOrFail();
    expect($d->status)->toBe('failed')
        ->and($d->next_retry_at)->toBeNull();
});

it('un evento globale (org null) NON viene inviato alle subscription per-org (no leak cross-tenant)', function () {
    Http::fake(['*' => Http::response('', 200)]);
    subscribe('https://hook.test/in', ['*']); // subscription org_wh

    // Evento globale (organization_id null), es. il meta-evento subject.erased.
    $event = app(AuditChainAppender::class)->append([
        'stream' => 'global',
        'event_type' => 'subject.erased',
        'risk_level' => 'high',
    ]);

    app(WebhookDispatcher::class)->dispatch($event);

    Http::assertNothingSent();
    expect(WebhookDelivery::query()->count())->toBe(0);
});

it('il retrier recupera una delivery orfana bloccata in sending (crash post-claim)', function () {
    Http::fake(['https://hook.test/*' => Http::response('', 200)]);
    config()->set('iam.audit.webhook_sending_timeout', 60);
    $sub = subscribe('https://hook.test/in', ['*']);

    // Simula un crash dopo il claim: riga 'sending' con updated_at vecchio.
    $event = sealEvent();
    $d = new WebhookDelivery;
    $d->forceFill(['subscription_id' => $sub->id, 'event_uuid' => $event->uuid, 'status' => 'sending', 'attempt' => 0])->save();
    WebhookDelivery::query()->whereKey($d->id)->update(['updated_at' => now()->subMinutes(10)]);

    $retried = app(WebhookRetrier::class)->retryDue();

    expect($retried)->toBe(1)
        ->and(WebhookDelivery::query()->findOrFail($d->id)->status)->toBe('delivered');
});

it('dopo la soglia di tentativi la delivery va in DLQ (failed)', function () {
    config()->set('iam.audit.webhook_max_attempts', 2);
    Http::fake(['https://hook.test/*' => Http::response('boom', 500)]);
    subscribe('https://hook.test/in', ['*']);

    app(WebhookDispatcher::class)->dispatch(sealEvent()); // attempt 1 → retrying
    WebhookDelivery::query()->update(['next_retry_at' => now()->subMinute()]);
    app(WebhookRetrier::class)->retryDue();                // attempt 2 → soglia → failed

    expect(WebhookDelivery::query()->where('status', 'failed')->count())->toBe(1);
});
