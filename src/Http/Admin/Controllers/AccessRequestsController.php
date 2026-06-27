<?php

declare(strict_types=1);

namespace Padosoft\Iam\Http\Admin\Controllers;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Padosoft\Iam\Domain\Governance\Requests\AccessRequestService;
use Padosoft\Iam\Domain\Governance\Requests\Models\AccessRequest;
use Padosoft\Iam\Domain\Governance\Requests\RequestCatalog;
use Padosoft\Iam\Http\Admin\AdminController;
use Padosoft\Iam\Http\Admin\Support\ApiProblemException;

/**
 * Admin API — Access Request self-service (doc 16 §3, doc 14 §4). Catalogo default-deny per il
 * richiedente, submit, e inbox approvazioni (approve/reject). Le decisioni passano dal servizio di
 * dominio (M8.4): grant time-boxed all'approvazione, niente self-approval, transazioni + lock.
 */
final class AccessRequestsController extends AdminController
{
    public function __construct(
        private readonly AccessRequestService $service,
        private readonly RequestCatalog $catalog,
    ) {}

    public function index(Request $request): JsonResponse
    {
        $query = AccessRequest::query();
        $org = $this->context($request)->organizationId;
        if ($org !== null) {
            $query->where('organization_id', $org);
        }
        if (is_string($request->query('status')) && $request->query('status') !== '') {
            $query->where('status', $request->query('status'));
        }

        return $this->paginate($query, $request, fn (Model $r): array => $r instanceof AccessRequest ? $this->summary($r) : []);
    }

    public function catalog(Request $request): JsonResponse
    {
        $ctx = $this->context($request);
        $roles = $this->catalog->visibleRoles($ctx->actor, $ctx->organizationId);

        return $this->ok(['roles' => array_map(static fn ($role): array => [
            'full_key' => $role->full_key, 'label' => $role->label, 'app_key' => $role->app_key,
        ], $roles)]);
    }

    public function store(Request $request): JsonResponse
    {
        $role = $request->input('role_key');
        if (!is_string($role) || $role === '') {
            throw ApiProblemException::unprocessable('Campo role_key obbligatorio.', ['role_key' => ['role_key è obbligatorio']]);
        }
        $justification = $request->input('justification');
        $ctx = $this->context($request);

        $accessRequest = $this->runDomain(
            fn () => $this->service->submit($ctx->actor, $role, is_string($justification) ? $justification : null, $ctx->organizationId),
        );

        $this->audit($request, 'iam.access_request.submitted', 'access_request', $accessRequest->id, ['role_key' => $role]);

        return $this->ok($this->summary($accessRequest), 201);
    }

    public function approve(Request $request, string $accessRequest): JsonResponse
    {
        $model = $this->find($request, $accessRequest);
        // InvalidArgument (es. max_duration malformata) → 422; conflitti di stato → 409 (via runDomain).
        $grant = $this->runDomain(fn () => $this->service->approve($model, $this->context($request)->actorRef()));
        $this->audit($request, 'iam.access_request.approved', 'access_request', $model->id, ['grant_id' => $grant->id]);

        return $this->ok($this->summary($model->fresh() ?? $model));
    }

    public function reject(Request $request, string $accessRequest): JsonResponse
    {
        $model = $this->find($request, $accessRequest);
        $note = $request->input('note');
        $this->runDomain(fn () => $this->service->reject($model, $this->context($request)->actorRef(), is_string($note) ? $note : null));
        $this->audit($request, 'iam.access_request.rejected', 'access_request', $model->id, []);

        return $this->ok($this->summary($model->fresh() ?? $model));
    }

    private function find(Request $request, string $id): AccessRequest
    {
        $model = AccessRequest::query()->find($id);
        $org = $this->context($request)->organizationId;
        if ($model === null || ($org !== null && $model->organization_id !== $org)) {
            throw ApiProblemException::notFound("Richiesta \"{$id}\" non trovata.");
        }

        return $model;
    }

    /**
     * @return array<string, mixed>
     */
    private function summary(AccessRequest $r): array
    {
        return [
            'id' => $r->id, 'status' => $r->status,
            'requester' => $r->requester_type.':'.$r->requester_id,
            'application_key' => $r->application_key, 'role_key' => $r->role_key,
            'justification' => $r->justification, 'granted_grant_id' => $r->granted_grant_id,
            'decided_by' => $r->decided_by, 'decided_at' => $r->decided_at?->toIso8601String(),
        ];
    }
}
