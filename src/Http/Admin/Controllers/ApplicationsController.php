<?php

declare(strict_types=1);

namespace Padosoft\Iam\Http\Admin\Controllers;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Padosoft\Iam\Domain\Applications\Models\Application;
use Padosoft\Iam\Domain\Applications\Models\Manifest;
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
