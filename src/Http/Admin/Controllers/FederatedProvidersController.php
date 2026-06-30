<?php

declare(strict_types=1);

namespace Padosoft\Iam\Http\Admin\Controllers;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Padosoft\Iam\Contracts\Crypto\SecretCipher;
use Padosoft\Iam\Domain\Identity\Models\FederatedProvider;
use Padosoft\Iam\Http\Admin\AdminController;
use Padosoft\Iam\Http\Admin\Support\ApiProblemException;

/**
 * Admin API — Federated Providers (doc 16 §3.8, doc 19 §4). CRUD della config OIDC/Socialite per tenant.
 * Il `client_secret` è WRITE-ONLY: cifrato via SecretCipher (envelope M3) nella colonna text come JSON,
 * mai restituito (in lettura solo `has_secret`). Tenant-scoped (cross-tenant = 404); audit per mutazione.
 */
final class FederatedProvidersController extends AdminController
{
    private const DRIVERS = ['socialite', 'oidc', 'saml'];

    public function __construct(private readonly SecretCipher $cipher) {}

    public function index(Request $request): JsonResponse
    {
        $query = FederatedProvider::query();
        $org = $this->context($request)->organizationId;
        if ($org !== null) {
            $query->where('organization_id', $org);
        }

        return $this->paginate($query, $request, fn (Model $p): array => $p instanceof FederatedProvider ? $this->summary($p) : []);
    }

    public function store(Request $request): JsonResponse
    {
        $key = $this->requiredString($request, 'key');
        $driver = $request->input('driver');
        if (!is_string($driver) || !in_array($driver, self::DRIVERS, true)) {
            throw ApiProblemException::unprocessable('Campo driver obbligatorio (socialite|oidc|saml).', ['driver' => ['driver non valido']]);
        }

        try {
            $provider = FederatedProvider::create([
                'organization_id' => $this->context($request)->organizationId,
                'key' => $key,
                'driver' => $driver,
                'client_id' => $this->nullableString($request, 'client_id'),
                'redirect_uri' => $this->nullableString($request, 'redirect_uri'),
                'scopes' => $this->arrayInput($request, 'scopes'),
                'options' => $this->arrayInput($request, 'options'),
                'auto_link_policy' => $this->nullableString($request, 'auto_link_policy') ?? 'verified_email',
                'jit_policy' => $this->arrayInput($request, 'jit_policy'),
                'status' => $this->nullableString($request, 'status') ?? 'active',
            ]);
        } catch (UniqueConstraintViolationException) {
            throw ApiProblemException::conflict("Provider con key \"{$key}\" già esistente.");
        }

        $this->writeSecret($provider, $request->input('client_secret'));
        $this->audit($request, 'iam.federated_provider.created', 'federated_provider', $provider->id, ['key' => $key, 'driver' => $driver]);

        return $this->ok($this->summary($provider), 201);
    }

    public function show(Request $request, string $provider): JsonResponse
    {
        return $this->ok($this->summary($this->find($request, $provider)));
    }

    public function update(Request $request, string $provider): JsonResponse
    {
        $model = $this->find($request, $provider);
        $before = $this->summary($model);

        foreach (['client_id', 'redirect_uri', 'auto_link_policy', 'status'] as $field) {
            $value = $request->input($field);
            if (is_string($value) && $value !== '') {
                $model->setAttribute($field, $value);
            }
        }
        foreach (['scopes', 'options', 'jit_policy'] as $field) {
            $value = $request->input($field);
            if (is_array($value)) {
                $model->setAttribute($field, $value);
            }
        }
        $model->save();

        // Il secret è write-only: aggiornato solo se fornito, mai azzerato per omissione.
        $this->writeSecret($model, $request->input('client_secret'));
        $this->audit($request, 'iam.federated_provider.updated', 'federated_provider', $model->id, [], $before, $this->summary($model));

        return $this->ok($this->summary($model));
    }

    public function destroy(Request $request, string $provider): JsonResponse
    {
        $model = $this->find($request, $provider);
        $model->delete();
        $this->audit($request, 'iam.federated_provider.deleted', 'federated_provider', $model->id, []);

        return $this->ok(['id' => $model->id, 'deleted' => true]);
    }

    /**
     * Validazione di configurazione (discovery) — NON tocca il secret e non lo restituisce. Verifica i
     * campi minimi e, per OIDC, la presenza/forma dell'issuer/discovery URL. Il probe di rete reale è
     * delegato al runtime di login; qui si dà un feedback deterministico (niente flakiness in CI).
     */
    public function test(Request $request, string $provider): JsonResponse
    {
        $model = $this->find($request, $provider);
        $issues = [];

        if ($model->client_id === null || $model->client_id === '') {
            $issues[] = 'client_id non configurato';
        }
        if ($model->client_secret_encrypted === null) {
            $issues[] = 'client_secret non configurato';
        }
        if ($model->driver === 'oidc') {
            $options = $model->options ?? [];
            $discovery = $options['discovery_url'] ?? ($options['issuer'] ?? null);
            if (!is_string($discovery) || filter_var($discovery, FILTER_VALIDATE_URL) === false) {
                $issues[] = 'discovery_url/issuer mancante o non valido per il driver oidc';
            }
        }

        $this->audit($request, 'iam.federated_provider.tested', 'federated_provider', $model->id, ['ok' => $issues === []]);

        return $this->ok(['ok' => $issues === [], 'issues' => $issues]);
    }

    private function writeSecret(FederatedProvider $model, mixed $secret): void
    {
        if (!is_string($secret) || $secret === '') {
            return;
        }
        // Envelope SecretCipher serializzato nella colonna text; client_secret_encrypted è fuori da
        // fillable → forceFill (mai mass-assignable). Mai restituito in lettura.
        $envelope = json_encode($this->cipher->encrypt($secret), JSON_THROW_ON_ERROR);
        $model->forceFill(['client_secret_encrypted' => $envelope])->save();
    }

    private function find(Request $request, string $provider): FederatedProvider
    {
        $org = $this->context($request)->organizationId;
        $model = FederatedProvider::query()->where('key', $provider)->first() ?? FederatedProvider::query()->find($provider);
        if ($model === null || ($org !== null && $model->organization_id !== $org)) {
            throw ApiProblemException::notFound("Provider \"{$provider}\" non trovato.");
        }

        return $model;
    }

    private function requiredString(Request $request, string $key): string
    {
        $value = $request->input($key);
        if (!is_string($value) || $value === '' || strlen($value) > 255) {
            throw ApiProblemException::unprocessable("Campo {$key} obbligatorio (max 255).", [$key => ["{$key} è obbligatorio"]]);
        }

        return $value;
    }

    private function nullableString(Request $request, string $key): ?string
    {
        $value = $request->input($key);

        return is_string($value) && $value !== '' ? $value : null;
    }

    /**
     * @return array<array-key, mixed>|null
     */
    private function arrayInput(Request $request, string $key): ?array
    {
        $value = $request->input($key);

        return is_array($value) ? $value : null;
    }

    /**
     * @return array<string, mixed>
     */
    private function summary(FederatedProvider $p): array
    {
        return [
            'id' => $p->id, 'key' => $p->key, 'driver' => $p->driver,
            'client_id' => $p->client_id, 'redirect_uri' => $p->redirect_uri,
            'scopes' => $p->scopes, 'auto_link_policy' => $p->auto_link_policy,
            'status' => $p->status, 'organization_id' => $p->organization_id,
            'has_secret' => $p->client_secret_encrypted !== null, // mai il valore: write-only
        ];
    }
}
