<?php

declare(strict_types=1);

namespace Padosoft\Iam\Http\Admin\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Padosoft\Iam\Contracts\Authorization\AuthorizationEngine;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Iam\Http\Admin\AdminController;
use Padosoft\Iam\Http\Admin\Support\ApiProblemException;

/**
 * Admin API — Decisions / Policy Playground (doc 16 §3.15, doc 18 §8). Espone il PDP per il "what-if":
 * check (allow/deny + matched), explain (spiegazione passo-passo), e — col ReBAC nativo (M16) —
 * list-subjects ("chi può accedere a R?") / list-resources ("su cosa può agire S?"). Il PDP resta
 * l'autorità; qui è solo una superficie HTTP di interrogazione per l'Admin Panel.
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
        $relation = $this->stringInput($request, 'relation');
        if ($relation === null) {
            throw ApiProblemException::unprocessable('Campo relation obbligatorio.', ['relation' => ['relation è obbligatorio']]);
        }
        $object = $request->input('object');
        if (!is_array($object) || !is_string($object['type'] ?? null) || !is_string($object['id'] ?? null) || $object['id'] === '') {
            throw ApiProblemException::unprocessable('Campo object {type,id} obbligatorio.', ['object' => ['object.type e object.id sono obbligatori']]);
        }

        $subjects = [];
        foreach ($this->pdp->listSubjects($relation, $object['type'], $object['id']) as $subject) {
            $subjects[] = ['type' => $subject->type, 'id' => $subject->id];
        }

        return $this->ok(['subjects' => $subjects]);
    }

    public function listResources(Request $request): JsonResponse
    {
        $relation = $this->stringInput($request, 'relation');
        if ($relation === null) {
            throw ApiProblemException::unprocessable('Campo relation obbligatorio.', ['relation' => ['relation è obbligatorio']]);
        }
        $subject = $request->input('subject');
        if (!is_array($subject) || !is_string($subject['id'] ?? null) || $subject['id'] === '') {
            throw ApiProblemException::unprocessable('Campo subject {type,id} obbligatorio.', ['subject' => ['subject.id è obbligatorio']]);
        }
        $type = is_string($subject['type'] ?? null) ? $subject['type'] : 'user';

        $resources = [];
        foreach ($this->pdp->listResources(new SubjectRef($type, $subject['id']), $relation) as $resource) {
            $resources[] = $resource;
        }

        return $this->ok(['resources' => $resources]);
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
            // ReBAC (doc 18 §7): relation-diretta opzionale; l'object è derivato da `resource`.
            'relation' => $this->stringInput($request, 'relation'),
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
