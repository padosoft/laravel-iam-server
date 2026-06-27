<?php

declare(strict_types=1);

namespace Padosoft\Iam\Http\Admin\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Padosoft\Iam\Contracts\Authorization\AuthorizationEngine;
use Padosoft\Iam\Http\Admin\AdminController;
use Padosoft\Iam\Http\Admin\Support\ApiProblemException;

/**
 * Admin API — Decisions / Policy Playground (doc 16 §3.15). Espone il PDP per il "what-if": check
 * (allow/deny + matched), explain (con la spiegazione passo-passo). Il PDP resta l'autorità; qui è
 * solo una superficie HTTP di interrogazione per l'Admin Panel. list-subjects/list-resources sono
 * ReBAC (v2) → 501.
 */
final class DecisionsController extends AdminController
{
    public function __construct(private readonly AuthorizationEngine $pdp) {}

    public function check(Request $request): JsonResponse
    {
        return $this->ok($this->decide($request, explain: false));
    }

    public function explain(Request $request): JsonResponse
    {
        return $this->ok($this->decide($request, explain: true));
    }

    public function listSubjects(Request $request): JsonResponse
    {
        throw new ApiProblemException(501, 'Not Implemented', 'list-subjects richiede il ReBAC reverse-index (v2).');
    }

    public function listResources(Request $request): JsonResponse
    {
        throw new ApiProblemException(501, 'Not Implemented', 'list-resources richiede il ReBAC reverse-index (v2).');
    }

    /**
     * @return array<string, mixed>
     */
    private function decide(Request $request, bool $explain): array
    {
        $subject = $request->input('subject');
        if (!is_array($subject) || !is_string($subject['id'] ?? null) || $subject['id'] === '' || strlen($subject['id']) > 255) {
            throw ApiProblemException::unprocessable('Campo subject.id obbligatorio (max 255).', ['subject' => ['subject.id è obbligatorio (max 255)']]);
        }
        $permission = $request->input('permission');
        if (!is_string($permission) || $permission === '' || strlen($permission) > 255) {
            throw ApiProblemException::unprocessable('Campo permission obbligatorio (max 255).', ['permission' => ['permission è obbligatorio (max 255)']]);
        }

        $context = $request->input('context');
        $resource = $request->input('resource');

        return $this->pdp->check([
            'subject' => ['type' => is_string($subject['type'] ?? null) ? $subject['type'] : 'user', 'id' => $subject['id']],
            'permission' => $permission,
            'organization' => $this->stringInput($request, 'organization'),
            'application' => $this->stringInput($request, 'application'),
            'resource' => $this->resourceRef($resource),
            'context' => is_array($context) ? $context : [],
            'current_aal' => $this->stringInput($request, 'current_aal') ?? 'aal1',
            'explain' => $explain,
        ]);
    }

    private function stringInput(Request $request, string $key): ?string
    {
        $value = $request->input($key);

        return is_string($value) && $value !== '' ? $value : null;
    }

    private function resourceRef(mixed $resource): ?string
    {
        if (is_string($resource) && $resource !== '') {
            return $resource;
        }
        // Forma {type, id} dal Playground → ref canonico "type:id".
        if (is_array($resource) && is_string($resource['id'] ?? null) && $resource['id'] !== '') {
            $type = is_string($resource['type'] ?? null) ? $resource['type'] : '';

            return $type !== '' ? $type.':'.$resource['id'] : $resource['id'];
        }

        return null;
    }
}
