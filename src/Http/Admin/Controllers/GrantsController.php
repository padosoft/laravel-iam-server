<?php

declare(strict_types=1);

namespace Padosoft\Iam\Http\Admin\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Padosoft\Iam\Domain\Authorization\Models\Grant;
use Padosoft\Iam\Http\Admin\AdminController;
use Padosoft\Iam\Http\Admin\Support\ApiProblemException;

/**
 * Admin API — Grants. Direct revoke of a single grant (doc 16 §3). Adding grants goes through the
 * policy wizard (policies-wizard/commit); this is the symmetric REMOVE operation the console needs to
 * take a role/permission away from a subject without opening an access-review campaign. Revocation is
 * fail-closed (Grant::revoke), idempotent, and audited with the actor.
 */
final class GrantsController extends AdminController
{
    public function revoke(Request $request, string $grant): JsonResponse
    {
        $org = $this->context($request)->organizationId;
        $model = Grant::query()->find($grant);

        // Tenant scoping: an org-bound admin may revoke only grants of its own org; a grant of another
        // tenant (or a global grant) is indistinguishable from a missing one (same 404, no enumeration).
        if ($model === null || ($org !== null && $model->organization_id !== $org)) {
            throw ApiProblemException::notFound("Grant \"{$grant}\" non trovato.");
        }

        // Idempotent: an already-revoked grant is a no-op (no second audit).
        if ($model->revoked_at === null) {
            $model->revoke($this->context($request)->actorRef());
            $this->audit($request, 'iam.grant.revoked', 'grant', $model->id, ['source' => 'admin-console'], ['revoked_at' => null], ['revoked_at' => $model->revoked_at?->toIso8601String()]);
        }

        return $this->ok($this->summary($model->fresh() ?? $model));
    }

    /**
     * @return array<string, mixed>
     */
    private function summary(Grant $g): array
    {
        return [
            'id' => $g->id,
            'subject_type' => $g->subject_type,
            'subject_id' => $g->subject_id,
            'privilege_type' => $g->privilege_type,
            'privilege_key' => $g->privilege_key,
            'effect' => $g->effect,
            'application_key' => $g->application_key,
            'is_privileged' => $g->is_privileged,
            'organization_id' => $g->organization_id,
            'revoked_at' => $g->revoked_at?->toIso8601String(),
        ];
    }
}
