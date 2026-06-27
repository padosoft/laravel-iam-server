<?php

declare(strict_types=1);

namespace Padosoft\Iam\Http\Admin\Controllers;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Padosoft\Iam\Domain\Applications\Manifest\ManifestRegistry;
use Padosoft\Iam\Domain\Applications\Models\Manifest;
use Padosoft\Iam\Http\Admin\AdminController;
use Padosoft\Iam\Http\Admin\Support\ApiProblemException;

/**
 * Admin API — Manifests + lifecycle (doc 16 §3.10, il moat). Submit/diff/approve/reject/apply/
 * rollback, wrapper sul ManifestRegistry (M6) che mantiene tutte le invarianti (approval gates,
 * il registry possiede il client OAuth, rollback con --approve, TOCTOU sotto lock). Tenant scoping.
 */
final class ManifestsController extends AdminController
{
    public function __construct(private readonly ManifestRegistry $registry) {}

    public function index(Request $request): JsonResponse
    {
        $query = Manifest::query();
        $org = $this->context($request)->organizationId;
        if ($org !== null) {
            $query->where('organization_id', $org);
        }
        if (is_string($request->query('application')) && $request->query('application') !== '') {
            $query->where('application_key', $request->query('application'));
        }

        return $this->paginate($query, $request, fn (Model $m): array => $m instanceof Manifest ? $this->summary($m) : []);
    }

    public function show(Request $request, string $manifest): JsonResponse
    {
        $model = $this->find($request, $manifest);

        return $this->ok($this->summary($model) + ['payload' => $model->payload, 'validation_errors' => $model->validation_errors]);
    }

    public function diff(Request $request, string $manifest): JsonResponse
    {
        $model = $this->find($request, $manifest);

        return $this->ok(['diff' => $this->registry->diff($model)]);
    }

    public function store(Request $request, string $app): JsonResponse
    {
        $raw = $request->input('manifest');
        $source = is_array($raw) ? $raw : $request->all();
        // Normalizza a chiavi-stringa (un payload JSON ha sempre chiavi string; il guard soddisfa
        // anche la firma array<string, mixed> di ManifestRegistry::submit).
        $payload = [];
        foreach ($source as $k => $v) {
            if (is_string($k)) {
                $payload[$k] = $v;
            }
        }
        $ctx = $this->context($request);

        $manifest = $this->runDomain(fn (): Manifest => $this->registry->submit($payload, $ctx->actorRef(), $ctx->organizationId));
        $this->audit($request, 'iam.manifest.submitted', 'manifest', $manifest->id, ['application_key' => $manifest->application_key, 'version' => $manifest->version]);

        return $this->ok($this->summary($manifest) + ['validation_errors' => $manifest->validation_errors], 201);
    }

    public function approve(Request $request, string $manifest): JsonResponse
    {
        $model = $this->find($request, $manifest);
        $ok = $this->runDomain(fn (): bool => $this->registry->approve($model, $this->context($request)->actorRef()));
        $this->audit($request, 'iam.manifest.approved', 'manifest', $model->id, ['ok' => $ok]);

        return $this->ok($this->summary($model->fresh() ?? $model));
    }

    public function reject(Request $request, string $manifest): JsonResponse
    {
        $model = $this->find($request, $manifest);
        $this->runDomain(fn (): bool => $this->registry->reject($model, $this->context($request)->actorRef()));
        $this->audit($request, 'iam.manifest.rejected', 'manifest', $model->id, []);

        return $this->ok($this->summary($model->fresh() ?? $model));
    }

    public function apply(Request $request, string $manifest): JsonResponse
    {
        $model = $this->find($request, $manifest);
        $app = $this->runDomain(fn () => $this->registry->apply($model));
        $this->audit($request, 'iam.manifest.applied', 'manifest', $model->id, ['application_id' => $app->id]);

        return $this->ok($this->summary($model->fresh() ?? $model) + ['application_id' => $app->id]);
    }

    public function rollback(Request $request, string $manifest): JsonResponse
    {
        $model = $this->find($request, $manifest);
        $approved = $request->boolean('approve');
        $app = $this->runDomain(fn () => $this->registry->rollback($model->application_key, $approved));
        if ($app === null) {
            throw ApiProblemException::conflict('Rollback non eseguito (nessuna versione precedente o approvazione mancante).');
        }
        $this->audit($request, 'iam.manifest.rolledback', 'application', $app->id, ['application_key' => $model->application_key]);

        return $this->ok(['application_id' => $app->id, 'application_key' => $model->application_key]);
    }

    private function find(Request $request, string $manifest): Manifest
    {
        $model = Manifest::query()->find($manifest);
        $org = $this->context($request)->organizationId;
        if ($model === null || ($org !== null && $model->organization_id !== $org)) {
            throw ApiProblemException::notFound("Manifest \"{$manifest}\" non trovato.");
        }

        return $model;
    }

    /**
     * @return array<string, mixed>
     */
    private function summary(Manifest $m): array
    {
        return [
            'id' => $m->id, 'application_key' => $m->application_key, 'version' => $m->version,
            'status' => $m->status, 'requires_approval' => $m->requires_approval,
            'organization_id' => $m->organization_id,
        ];
    }
}
