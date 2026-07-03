<?php

declare(strict_types=1);

namespace Padosoft\Iam\Http\Admin\Controllers;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Padosoft\Iam\Domain\Organizations\Models\Organization;
use Padosoft\Iam\Http\Admin\AdminController;
use Padosoft\Iam\Http\Admin\Support\ApiProblemException;

/**
 * Admin API — Organizations / tenants (doc 09/10). First-class multi-tenancy: an org scopes groups,
 * memberships and grants. CRUD only; a "delete" suspends (status=suspended) rather than hard-deleting,
 * so existing grants/memberships/audit are never orphaned. Every mutation is audited.
 */
final class OrganizationsController extends AdminController
{
    public function index(Request $request): JsonResponse
    {
        return $this->paginate(Organization::query(), $request, fn (Model $o): array => $o instanceof Organization ? $this->summary($o) : []);
    }

    public function store(Request $request): JsonResponse
    {
        $key = $this->requiredString($request, 'key');
        $name = $this->requiredString($request, 'name');

        // The unique (key) is enforced by the DB → a duplicate is a 409, not a 500 (no TOCTOU).
        try {
            $org = Organization::create(['key' => $key, 'name' => $name]);
        } catch (UniqueConstraintViolationException) {
            throw ApiProblemException::conflict("Organizzazione con key \"{$key}\" già esistente.");
        }

        $this->audit($request, 'iam.organization.created', 'organization', $org->id, ['key' => $key]);

        return $this->ok($this->summary($org), 201);
    }

    public function show(Request $request, string $organization): JsonResponse
    {
        return $this->ok($this->summary($this->find($organization)));
    }

    public function update(Request $request, string $organization): JsonResponse
    {
        $model = $this->find($organization);
        $before = $this->summary($model);

        $name = $request->input('name');
        if (is_string($name) && $name !== '') {
            $model->name = $name;
        }
        $status = $request->input('status');
        if (is_string($status) && in_array($status, ['active', 'suspended'], true)) {
            $model->status = $status;
        }
        $model->save();

        $this->audit($request, 'iam.organization.updated', 'organization', $model->id, [], $before, $this->summary($model));

        return $this->ok($this->summary($model));
    }

    public function destroy(Request $request, string $organization): JsonResponse
    {
        $model = $this->find($organization);
        if ($model->status === 'suspended') {
            throw ApiProblemException::conflict('Organizzazione già sospesa.');
        }
        // Soft: suspend (never hard-delete a tenant — grants/memberships/audit must survive).
        $model->status = 'suspended';
        $model->save();
        $this->audit($request, 'iam.organization.suspended', 'organization', $model->id, []);

        return $this->ok(['id' => $model->id, 'status' => 'suspended']);
    }

    private function find(string $organization): Organization
    {
        // Lookup by key first (the human handle), then by id.
        $model = Organization::query()->where('key', $organization)->first()
            ?? Organization::query()->find($organization);
        if ($model === null) {
            throw ApiProblemException::notFound("Organizzazione \"{$organization}\" non trovata.");
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

    /**
     * @return array<string, mixed>
     */
    private function summary(Organization $o): array
    {
        return [
            'id' => $o->id,
            'key' => $o->key,
            'name' => $o->name,
            'status' => $o->status,
            'created_at' => $o->created_at?->toIso8601String(),
        ];
    }
}
