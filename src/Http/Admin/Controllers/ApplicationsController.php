<?php

declare(strict_types=1);

namespace Padosoft\Iam\Http\Admin\Controllers;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Padosoft\Iam\Domain\Applications\Models\Application;
use Padosoft\Iam\Domain\Applications\Models\Manifest;
use Padosoft\Iam\Domain\OAuth\Models\OauthClient;
use Padosoft\Iam\Http\Admin\AdminController;
use Padosoft\Iam\Http\Admin\Support\ApiProblemException;

/**
 * Admin API — Applications (doc 16 §3.5). Lettura del registry delle app (il moat): lista, dettaglio
 * e manifest corrente applicato. Le mutazioni dell'app passano dal manifest (vedi ManifestsController),
 * non da edit diretti → single source of truth. Tenant scoping per `organization_id`.
 */
final class ApplicationsController extends AdminController
{
    public function index(Request $request): JsonResponse
    {
        $query = Application::query();
        $org = $this->context($request)->organizationId;
        if ($org !== null) {
            $query->where('organization_id', $org);
        }

        return $this->paginate($query, $request, fn (Model $a): array => $a instanceof Application ? $this->summary($a) : []);
    }

    public function show(Request $request, string $app): JsonResponse
    {
        return $this->ok($this->summary($this->find($request, $app)));
    }

    public function manifest(Request $request, string $app): JsonResponse
    {
        $model = $this->find($request, $app);
        if ($model->current_manifest_id === null) {
            throw ApiProblemException::notFound('Nessun manifest applicato per questa app.');
        }
        $manifest = Manifest::query()->find($model->current_manifest_id);
        if ($manifest === null) {
            throw ApiProblemException::notFound('Manifest corrente non trovato.');
        }

        return $this->ok([
            'id' => $manifest->id, 'application_key' => $manifest->application_key,
            'version' => $manifest->version, 'status' => $manifest->status, 'payload' => $manifest->payload,
        ]);
    }

    /** Credential status of the app's OAuth client (client_id, secret expiry, grace, rotation). */
    public function client(Request $request, string $app): JsonResponse
    {
        return $this->ok($this->clientSummary($this->clientFor($this->find($request, $app))));
    }

    /** Rotate the app's client_secret: issue a new one (returned once), keep the old valid for the grace. */
    public function rotateSecret(Request $request, string $app): JsonResponse
    {
        $client = $this->clientFor($this->find($request, $app));
        if ($client->revoked_at !== null) {
            throw ApiProblemException::conflict('Client revocato: non è ruotabile.');
        }
        if (!$client->is_confidential) {
            throw ApiProblemException::unprocessable('Solo i client confidential hanno un secret da ruotare.');
        }
        // Serializza le rotazioni: una seconda rotazione mentre il secret precedente è ancora nel grace lo
        // scarterebbe, ORFANEGGIANDO il secret originale (un'app non ancora migrata si romperebbe prima della
        // sua finestra). Blocca finché il grace non scade (o il client non viene revocato).
        if ($client->previousSecretActive()) {
            throw ApiProblemException::conflict('Rotazione già in corso: il secret precedente è valido (grace) fino a '.$client->secret_previous_expires_at?->toIso8601String().'. Completa il rollover prima di ruotare di nuovo.');
        }
        $plain = $client->rotateSecret(self::intConfig('iam.oauth.client_secret_grace', 259200), self::ttlSeconds());
        $this->audit($request, 'iam.client.secret_rotated', 'oauth_client', $client->id, ['client_id' => $client->client_id]);

        // client_secret shown ONCE (never persisted in clear, never re-shown, not in the audit metadata).
        return $this->ok($this->clientSummary($client) + ['client_secret' => $plain]);
    }

    /** Revoke the app's OAuth client (kills it immediately; not reversible via this API). */
    public function revokeClient(Request $request, string $app): JsonResponse
    {
        $client = $this->clientFor($this->find($request, $app));
        if ($client->revoked_at !== null) {
            throw ApiProblemException::conflict('Client già revocato.');
        }
        $client->revoke();
        $this->audit($request, 'iam.client.revoked', 'oauth_client', $client->id, ['client_id' => $client->client_id]);

        return $this->ok(['client_id' => $client->client_id, 'revoked' => true]);
    }

    private function clientFor(Application $app): OauthClient
    {
        $client = OauthClient::query()->where('client_id', 'cli_'.$app->key)->first();
        if ($client === null) {
            throw ApiProblemException::notFound('Questa app non ha un client OAuth (client public o manifest non ancora applicato).');
        }

        return $client;
    }

    private static function ttlSeconds(): ?int
    {
        $ttl = config('iam.oauth.client_secret_ttl');

        // Solo un TTL positivo ha senso; non-numerico o <= 0 → nessuna scadenza (null).
        return is_numeric($ttl) && (int) $ttl > 0 ? (int) $ttl : null;
    }

    private static function intConfig(string $key, int $default): int
    {
        $value = config($key, $default);

        return is_numeric($value) ? (int) $value : $default;
    }

    /**
     * @return array<string, mixed>
     */
    private function clientSummary(OauthClient $c): array
    {
        return [
            'client_id' => $c->client_id,
            'is_confidential' => $c->is_confidential,
            'secret_expires_at' => $c->secret_expires_at?->toIso8601String(),
            'secret_rotated_at' => $c->secret_rotated_at?->toIso8601String(),
            'grace_active' => $c->previousSecretActive(),
            'grace_until' => $c->previousSecretActive() ? $c->secret_previous_expires_at?->toIso8601String() : null,
            'revoked_at' => $c->revoked_at?->toIso8601String(),
            'secret_status' => self::secretStatus($c),
        ];
    }

    /** ok | expiring | expired | revoked | public — drives the console rotation alerts. */
    private static function secretStatus(OauthClient $c): string
    {
        if ($c->revoked_at !== null) {
            return 'revoked';
        }
        if (!$c->is_confidential) {
            return 'public';
        }
        $exp = $c->secret_expires_at;
        if ($exp === null) {
            return 'ok';
        }
        if ($exp->isPast()) {
            return 'expired';
        }

        return $exp->lte(now()->addDays(self::intConfig('iam.oauth.client_secret_warn_days', 14))) ? 'expiring' : 'ok';
    }

    private function find(Request $request, string $app): Application
    {
        $model = Application::query()->where('key', $app)->first() ?? Application::query()->find($app);
        $org = $this->context($request)->organizationId;
        if ($model === null || ($org !== null && $model->organization_id !== $org)) {
            throw ApiProblemException::notFound("Applicazione \"{$app}\" non trovata.");
        }

        return $model;
    }

    /**
     * @return array<string, mixed>
     */
    private function summary(Application $a): array
    {
        return [
            'id' => $a->id, 'key' => $a->key, 'name' => $a->name, 'type' => $a->type,
            'risk_level' => $a->risk_level, 'status' => $a->status,
            'organization_id' => $a->organization_id, 'current_manifest_id' => $a->current_manifest_id,
        ];
    }
}
