<?php

declare(strict_types=1);

namespace Padosoft\Iam\Http\Admin\Controllers;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Padosoft\Iam\Contracts\Crypto\SecretCipher;
use Padosoft\Iam\Domain\Audit\Models\AuditEvent;
use Padosoft\Iam\Domain\Audit\Webhooks\Models\WebhookDelivery;
use Padosoft\Iam\Domain\Audit\Webhooks\Models\WebhookSubscription;
use Padosoft\Iam\Domain\Audit\Webhooks\WebhookRetrier;
use Padosoft\Iam\Domain\Audit\Webhooks\WebhookSender;
use Padosoft\Iam\Domain\Audit\Webhooks\WebhookUrlGuard;
use Padosoft\Iam\Http\Admin\AdminController;
use Padosoft\Iam\Http\Admin\Support\ApiProblemException;

/**
 * Admin API — Webhooks (doc 16 §3.24, doc 19 §7). CRUD sopra il backend webhook già completo (M7):
 * dispatcher/retrier/sender/signer + URL-guard anti-SSRF. Il `secret` HMAC è WRITE-ONLY (envelope
 * SecretCipher, mai restituito). Test-delivery passa dall'URL-guard come una consegna reale; il replay
 * di una delivery in DLQ riusa il WebhookRetrier. Tenant-scoped (cross-tenant = 404); audit per mutazione.
 */
final class WebhooksController extends AdminController
{
    public function __construct(
        private readonly SecretCipher $cipher,
        private readonly WebhookSender $sender,
        private readonly WebhookRetrier $retrier,
        private readonly WebhookUrlGuard $urlGuard,
    ) {}

    public function index(Request $request): JsonResponse
    {
        $query = WebhookSubscription::query();
        $org = $this->context($request)->organizationId;
        if ($org !== null) {
            $query->where('organization_id', $org);
        }

        return $this->paginate($query, $request, fn (Model $s): array => $s instanceof WebhookSubscription ? $this->summary($s) : []);
    }

    public function store(Request $request): JsonResponse
    {
        $url = $this->requireSafeUrl($request);
        $filters = $request->input('event_filters');
        if (!is_array($filters) || $filters === []) {
            throw ApiProblemException::unprocessable('Campo event_filters obbligatorio (lista di pattern).', ['event_filters' => ['event_filters è obbligatorio']]);
        }
        $secret = $request->input('secret');
        if (!is_string($secret) || $secret === '') {
            throw ApiProblemException::unprocessable('Campo secret obbligatorio (segreto HMAC).', ['secret' => ['secret è obbligatorio']]);
        }

        $subscription = WebhookSubscription::query()->create([
            'organization_id' => $this->context($request)->organizationId,
            'url' => $url,
            'secret_encrypted' => $this->cipher->encrypt($secret),
            'event_filters' => array_values(array_filter($filters, 'is_string')),
            'status' => $this->nullableString($request, 'status') ?? 'active',
        ]);

        $this->audit($request, 'iam.webhook.created', 'webhook', $subscription->id, ['url' => $url]);

        return $this->ok($this->summary($subscription), 201);
    }

    public function show(Request $request, string $subscription): JsonResponse
    {
        return $this->ok($this->summary($this->find($request, $subscription)));
    }

    public function update(Request $request, string $subscription): JsonResponse
    {
        $model = $this->find($request, $subscription);
        $before = $this->summary($model);

        $url = $request->input('url');
        if (is_string($url) && $url !== '') {
            if (!$this->urlGuard->isSafe($url)) {
                throw ApiProblemException::unprocessable('URL non sicuro (SSRF/scheme): usa https verso un host pubblico.');
            }
            $model->url = $url;
        }
        $filters = $request->input('event_filters');
        if (is_array($filters) && $filters !== []) {
            $model->event_filters = array_values(array_filter($filters, 'is_string'));
        }
        $status = $request->input('status');
        if (is_string($status) && $status !== '') {
            $model->status = $status;
        }
        $model->save();

        // Secret write-only: ruotato solo se fornito (mai azzerato per omissione).
        $secret = $request->input('secret');
        if (is_string($secret) && $secret !== '') {
            $model->forceFill(['secret_encrypted' => $this->cipher->encrypt($secret)])->save();
            $this->audit($request, 'iam.webhook.secret_rotated', 'webhook', $model->id, []);
        }

        $this->audit($request, 'iam.webhook.updated', 'webhook', $model->id, [], $before, $this->summary($model));

        return $this->ok($this->summary($model));
    }

    public function destroy(Request $request, string $subscription): JsonResponse
    {
        $model = $this->find($request, $subscription);
        $model->delete();
        $this->audit($request, 'iam.webhook.deleted', 'webhook', $model->id, []);

        return $this->ok(['id' => $model->id, 'deleted' => true]);
    }

    /**
     * Invio di un evento di prova: passa dall'URL-guard e dal signer come una consegna reale (M7). Crea
     * una delivery dedicata per un evento sintetico (non sigillato in catena) e ne tenta la consegna.
     */
    public function test(Request $request, string $subscription): JsonResponse
    {
        $model = $this->find($request, $subscription);

        $event = new AuditEvent;
        $event->forceFill([
            'uuid' => (string) Str::ulid(),
            'stream' => $model->organization_id ?? 'global',
            'event_type' => 'iam.webhook.test',
            'organization_id' => $model->organization_id,
            'risk_level' => 'low',
            'occurred_at' => now(),
            'after_json' => ['test' => true],
        ]);

        $delivery = WebhookDelivery::query()->firstOrCreate([
            'subscription_id' => $model->id,
            'event_uuid' => $event->uuid,
        ]);

        $this->sender->send($model, $delivery, $event);
        $this->audit($request, 'iam.webhook.tested', 'webhook', $model->id, []);

        return $this->ok($this->deliverySummary($delivery->fresh() ?? $delivery));
    }

    public function deliveries(Request $request, string $subscription): JsonResponse
    {
        $model = $this->find($request, $subscription);

        return $this->paginate(
            WebhookDelivery::query()->where('subscription_id', $model->id),
            $request,
            fn (Model $d): array => $d instanceof WebhookDelivery ? $this->deliverySummary($d) : [],
        );
    }

    /**
     * DLQ replay (doc 19 §7): rimette in coda una delivery `failed` e riusa il WebhookRetrier per
     * riconsegnarla. Solo le delivery in DLQ sono riproducibili (409 altrimenti).
     */
    public function replay(Request $request, string $delivery): JsonResponse
    {
        $model = WebhookDelivery::query()->find($delivery);
        if ($model === null) {
            throw ApiProblemException::notFound("Delivery \"{$delivery}\" non trovata.");
        }
        // Tenant scoping via la subscription della delivery (cross-tenant = 404 indistinguibile).
        $this->find($request, $model->subscription_id);

        if ($model->status !== 'failed') {
            throw ApiProblemException::conflict('Solo una delivery in DLQ (failed) può essere riprodotta.');
        }

        $model->forceFill(['status' => 'retrying', 'next_retry_at' => now()])->save();
        $retried = $this->retrier->retryDue();

        $this->audit($request, 'iam.webhook.delivery_replayed', 'webhook_delivery', $model->id, []);

        return $this->ok(['id' => $model->id, 'retried' => $retried, 'status' => $model->fresh()?->status]);
    }

    private function requireSafeUrl(Request $request): string
    {
        $url = $request->input('url');
        if (!is_string($url) || $url === '') {
            throw ApiProblemException::unprocessable('Campo url obbligatorio.', ['url' => ['url è obbligatorio']]);
        }
        if (!$this->urlGuard->isSafe($url)) {
            throw ApiProblemException::unprocessable('URL non sicuro (SSRF/scheme): usa https verso un host pubblico.');
        }

        return $url;
    }

    private function find(Request $request, string $subscription): WebhookSubscription
    {
        $org = $this->context($request)->organizationId;
        $model = WebhookSubscription::query()->find($subscription);
        if ($model === null || ($org !== null && $model->organization_id !== $org)) {
            throw ApiProblemException::notFound("Webhook \"{$subscription}\" non trovato.");
        }

        return $model;
    }

    private function nullableString(Request $request, string $key): ?string
    {
        $value = $request->input($key);

        return is_string($value) && $value !== '' ? $value : null;
    }

    /**
     * @return array<string, mixed>
     */
    private function summary(WebhookSubscription $s): array
    {
        return [
            'id' => $s->id, 'url' => $s->url, 'event_filters' => $s->event_filters,
            'status' => $s->status, 'organization_id' => $s->organization_id,
            'has_secret' => true, // secret HMAC write-only: mai restituito
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function deliverySummary(WebhookDelivery $d): array
    {
        return [
            'id' => $d->id, 'subscription_id' => $d->subscription_id, 'event_uuid' => $d->event_uuid,
            'attempt' => $d->attempt, 'status' => $d->status, 'response_code' => $d->response_code,
            'next_retry_at' => $d->next_retry_at?->toIso8601String(),
            'delivered_at' => $d->delivered_at?->toIso8601String(),
        ];
    }
}
