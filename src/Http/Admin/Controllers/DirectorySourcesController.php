<?php

declare(strict_types=1);

namespace Padosoft\Iam\Http\Admin\Controllers;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Padosoft\Iam\Contracts\Crypto\SecretCipher;
use Padosoft\Iam\Domain\Directory\Models\DirectorySource;
use Padosoft\Iam\Http\Admin\AdminController;
use Padosoft\Iam\Http\Admin\Support\ApiProblemException;

/**
 * Admin API — Directory Sources (doc 16 §3.9, doc 19 §5). CRUD della config LDAP/AD; il `bind_secret` è
 * WRITE-ONLY (envelope SecretCipher, M3). I trigger sync/test sono DELEGATI al modulo `-directory`: se
 * non attivo (config `iam.directory.enabled`) rispondono 409 (degradazione pulita, non 500). La CRUD
 * della config resta disponibile anche senza il modulo. Tenant-scoped (cross-tenant = 404); audit per
 * mutazione.
 */
final class DirectorySourcesController extends AdminController
{
    private const TYPES = ['ldap', 'scim', 'saml'];

    public function __construct(private readonly SecretCipher $cipher) {}

    public function index(Request $request): JsonResponse
    {
        $query = DirectorySource::query();
        $org = $this->context($request)->organizationId;
        if ($org !== null) {
            $query->where('organization_id', $org);
        }

        return $this->paginate($query, $request, fn (Model $s): array => $s instanceof DirectorySource ? $this->summary($s) : []);
    }

    public function store(Request $request): JsonResponse
    {
        $key = $this->requiredString($request, 'key');
        $type = $request->input('type');
        if ($type !== null && (!is_string($type) || !in_array($type, self::TYPES, true))) {
            throw ApiProblemException::unprocessable('Campo type non valido (ldap|scim|saml).', ['type' => ['type non valido']]);
        }

        try {
            $source = DirectorySource::create([
                'organization_id' => $this->context($request)->organizationId,
                'key' => $key,
                'name' => $this->requiredString($request, 'name'),
                'type' => is_string($type) ? $type : 'ldap',
                'host' => $this->requiredString($request, 'host'),
                'base_dn' => $this->requiredString($request, 'base_dn'),
                'bind_dn' => $this->nullableString($request, 'bind_dn'),
                'filters' => is_array($request->input('filters')) ? $request->input('filters') : null,
                'group_mapping_ref' => $this->nullableString($request, 'group_mapping_ref'),
                'sync_mode' => $this->nullableString($request, 'sync_mode') ?? 'jit',
                'status' => $this->nullableString($request, 'status') ?? 'active',
            ]);
        } catch (UniqueConstraintViolationException) {
            throw ApiProblemException::conflict("Directory source con key \"{$key}\" già esistente.");
        }

        $this->writeSecret($source, $request->input('bind_secret'));
        $this->audit($request, 'iam.directory_source.created', 'directory_source', $source->id, ['key' => $key]);

        return $this->ok($this->summary($source), 201);
    }

    public function show(Request $request, string $source): JsonResponse
    {
        return $this->ok($this->summary($this->find($request, $source)));
    }

    public function update(Request $request, string $source): JsonResponse
    {
        $model = $this->find($request, $source);
        $before = $this->summary($model);

        foreach (['name', 'host', 'base_dn', 'bind_dn', 'group_mapping_ref', 'sync_mode', 'status'] as $field) {
            $value = $request->input($field);
            if (is_string($value) && $value !== '') {
                $model->setAttribute($field, $value);
            }
        }
        if (is_array($request->input('filters'))) {
            $model->filters = $request->input('filters');
        }
        $model->save();

        $this->writeSecret($model, $request->input('bind_secret'));
        $this->audit($request, 'iam.directory_source.updated', 'directory_source', $model->id, [], $before, $this->summary($model));

        return $this->ok($this->summary($model));
    }

    public function destroy(Request $request, string $source): JsonResponse
    {
        $model = $this->find($request, $source);
        $model->delete();
        $this->audit($request, 'iam.directory_source.deleted', 'directory_source', $model->id, []);

        return $this->ok(['id' => $model->id, 'deleted' => true]);
    }

    /**
     * Trigger sync — delegato al modulo `-directory` (async via outbox). Senza il modulo → 409.
     * Qui marchiamo la sorgente `queued` e auditiamo; il modulo, quando presente, processa la coda.
     */
    public function sync(Request $request, string $source): JsonResponse
    {
        $model = $this->find($request, $source);
        $this->assertDirectoryActive();

        $model->forceFill(['last_sync_status' => 'queued', 'last_sync_at' => now()])->save();
        $this->audit($request, 'iam.directory.sync_started', 'directory_source', $model->id, []);

        return $this->ok(['id' => $model->id, 'sync_status' => 'queued'], 202);
    }

    /**
     * Test bind — delegato al modulo `-directory`. Senza il modulo → 409. Non restituisce mai il secret.
     */
    public function test(Request $request, string $source): JsonResponse
    {
        $model = $this->find($request, $source);
        $this->assertDirectoryActive();

        $issues = [];
        if ($model->bind_dn !== null && $model->bind_secret_encrypted === null) {
            $issues[] = 'bind_secret non configurato per il bind_dn fornito';
        }
        $this->audit($request, 'iam.directory.tested', 'directory_source', $model->id, ['ok' => $issues === []]);

        return $this->ok(['ok' => $issues === [], 'issues' => $issues]);
    }

    /** Fail-closed (degradazione pulita): senza il modulo `-directory` i trigger sono 409, non 500. */
    private function assertDirectoryActive(): void
    {
        if (config('iam.directory.enabled', false) !== true) {
            throw ApiProblemException::conflict('Modulo directory non attivo: installa/abilita padosoft/laravel-iam-directory.');
        }
    }

    private function writeSecret(DirectorySource $model, mixed $secret): void
    {
        if (!is_string($secret) || $secret === '') {
            return;
        }
        // bind_secret_encrypted è cast 'array' (colonna json) e fuori da fillable → forceFill l'envelope.
        $model->forceFill(['bind_secret_encrypted' => $this->cipher->encrypt($secret)])->save();
    }

    private function find(Request $request, string $source): DirectorySource
    {
        $org = $this->context($request)->organizationId;
        $model = DirectorySource::query()->where('key', $source)->first() ?? DirectorySource::query()->find($source);
        if ($model === null || ($org !== null && $model->organization_id !== $org)) {
            throw ApiProblemException::notFound("Directory source \"{$source}\" non trovato.");
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
     * @return array<string, mixed>
     */
    private function summary(DirectorySource $s): array
    {
        return [
            'id' => $s->id, 'key' => $s->key, 'name' => $s->name, 'type' => $s->type,
            'host' => $s->host, 'base_dn' => $s->base_dn, 'bind_dn' => $s->bind_dn,
            'sync_mode' => $s->sync_mode, 'status' => $s->status,
            'organization_id' => $s->organization_id,
            'last_sync_status' => $s->last_sync_status,
            'last_sync_at' => $s->last_sync_at?->toIso8601String(),
            'has_bind_secret' => $s->bind_secret_encrypted !== null, // mai il valore: write-only
        ];
    }
}
