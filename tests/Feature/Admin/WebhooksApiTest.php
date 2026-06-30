<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Padosoft\Iam\Contracts\Crypto\SecretCipher;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Iam\Domain\Audit\AuditChainAppender;
use Padosoft\Iam\Domain\Audit\Webhooks\Models\WebhookDelivery;
use Padosoft\Iam\Domain\Audit\Webhooks\Models\WebhookSubscription;
use Padosoft\Iam\Domain\Authorization\Models\Grant;
use Padosoft\Iam\Http\Admin\Support\AdminActorResolver;
use Padosoft\Iam\Http\Admin\Support\AdminContext;

uses(RefreshDatabase::class);

// Self-contained: resolver di test via X-Test-Auth (super admin, org null).
function whBind(): void
{
    app()->bind(AdminActorResolver::class, fn (): AdminActorResolver => new class implements AdminActorResolver
    {
        public function resolve(Request $request): ?AdminContext
        {
            $id = $request->headers->get('X-Test-Auth');

            return is_string($id) && $id !== '' ? new AdminContext(new SubjectRef('user', $id)) : null;
        }
    });
}

/** @param list<string> $permissions */
function whGrant(string $subjectId, array $permissions): void
{
    foreach ($permissions as $perm) {
        Grant::create([
            'subject_type' => 'user', 'subject_id' => $subjectId,
            'privilege_type' => 'permission', 'privilege_key' => $perm,
        ]);
    }
}

beforeEach(fn () => whBind());

it('rifiuta 403 fail-closed senza permesso', function () {
    $this->getJson('/api/iam/v1/webhooks', ['X-Test-Auth' => 'adm'])->assertStatus(403);
});

it('crea una subscription con secret write-only e rifiuta un URL SSRF', function () {
    whGrant('adm', ['iam:webhooks.read', 'iam:webhooks.manage']);

    $res = $this->postJson('/api/iam/v1/webhooks', [
        'url' => 'https://hook.test/in', 'event_filters' => ['grant.*'], 'secret' => 'whsec',
    ], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'w1']);
    $res->assertStatus(201)->assertJsonPath('data.has_secret', true)->assertJsonMissingPath('data.secret_encrypted');

    // URL SSRF (metadata link-local) → 422 (non viene mai persistito).
    $this->postJson('/api/iam/v1/webhooks', [
        'url' => 'http://169.254.169.254/x', 'event_filters' => ['*'], 'secret' => 's',
    ], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'w2'])->assertStatus(422);
});

it('test-delivery passa dall\'URL-guard e consegna (2xx → delivered)', function () {
    Http::fake(['https://hook.test/*' => Http::response('', 200)]);
    whGrant('adm', ['iam:webhooks.read', 'iam:webhooks.manage']);
    $id = $this->postJson('/api/iam/v1/webhooks', ['url' => 'https://hook.test/in', 'event_filters' => ['*'], 'secret' => 'whsec'], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'w1'])->json('data.id');

    $res = $this->postJson("/api/iam/v1/webhooks/{$id}/test", [], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 't1']);

    $res->assertOk()->assertJsonPath('data.status', 'delivered');
    Http::assertSentCount(1);
    expect(WebhookDelivery::query()->where('status', 'delivered')->count())->toBe(1);
});

it('elenca le deliveries di una subscription', function () {
    Http::fake(['https://hook.test/*' => Http::response('', 200)]);
    whGrant('adm', ['iam:webhooks.read', 'iam:webhooks.manage']);
    $id = $this->postJson('/api/iam/v1/webhooks', ['url' => 'https://hook.test/in', 'event_filters' => ['*'], 'secret' => 'whsec'], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'w1'])->json('data.id');
    $this->postJson("/api/iam/v1/webhooks/{$id}/test", [], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 't1']);

    $this->getJson("/api/iam/v1/webhooks/{$id}/deliveries", ['X-Test-Auth' => 'adm'])
        ->assertOk()->assertJsonStructure(['data', 'next_cursor']);
});

it('DLQ replay di una delivery failed la riconsegna (riusa il WebhookRetrier)', function () {
    Http::fake(['https://hook.test/*' => Http::response('', 200)]);
    whGrant('adm', ['iam:webhooks.read', 'iam:webhooks.manage']);

    $sub = WebhookSubscription::query()->create([
        'url' => 'https://hook.test/in',
        'secret_encrypted' => app(SecretCipher::class)->encrypt('whsec'),
        'event_filters' => ['*'],
    ]);
    // Evento reale sigillato + delivery in DLQ (failed) per quell'evento.
    $event = app(AuditChainAppender::class)->append(['stream' => 'global', 'event_type' => 'grant.assigned', 'risk_level' => 'high']);
    $delivery = new WebhookDelivery;
    $delivery->forceFill(['subscription_id' => $sub->id, 'event_uuid' => $event->uuid, 'status' => 'failed', 'attempt' => 5])->save();

    $res = $this->postJson("/api/iam/v1/webhooks/deliveries/{$delivery->id}/replay", [], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'r1']);

    $res->assertOk();
    expect(WebhookDelivery::query()->findOrFail($delivery->id)->status)->toBe('delivered');
});

it('replay di una delivery non in DLQ è 409', function () {
    whGrant('adm', ['iam:webhooks.read', 'iam:webhooks.manage']);
    $sub = WebhookSubscription::query()->create([
        'url' => 'https://hook.test/in',
        'secret_encrypted' => app(SecretCipher::class)->encrypt('whsec'),
        'event_filters' => ['*'],
    ]);
    $delivery = new WebhookDelivery;
    $delivery->forceFill(['subscription_id' => $sub->id, 'event_uuid' => 'evt_x', 'status' => 'delivered', 'attempt' => 1])->save();

    $this->postJson("/api/iam/v1/webhooks/deliveries/{$delivery->id}/replay", [], ['X-Test-Auth' => 'adm', 'Idempotency-Key' => 'r1'])
        ->assertStatus(409);
});
