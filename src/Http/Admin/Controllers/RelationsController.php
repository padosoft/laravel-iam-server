<?php

declare(strict_types=1);

namespace Padosoft\Iam\Http\Admin\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Iam\Domain\Authorization\Pdp\ResourceRef;
use Padosoft\Iam\Domain\Authorization\Relations\RelationWriter;
use Padosoft\Iam\Http\Admin\AdminController;
use Padosoft\Iam\Http\Admin\Support\ApiProblemException;

/**
 * Admin API — Relations (tuple ReBAC, doc 18 §8). Scrittura/revoca delle tuple `(subject, relation,
 * object)` che alimentano il motore nativo. Idempotente; tenant-scoped sull'org dell'attore; ogni
 * mutazione è audited (stream admin qui + stream authorization dal RelationWriter).
 */
final class RelationsController extends AdminController
{
    public function __construct(private readonly RelationWriter $writer) {}

    public function store(Request $request): JsonResponse
    {
        [$subject, $relation, $object] = $this->parseTuple($request);
        $condition = $this->stringKeyedArray($request->input('condition'));
        $ctx = $this->context($request);

        $tuple = $this->writer->grant(
            $subject,
            $relation,
            $object,
            $condition,
            $ctx->organizationId,
            $ctx->actorRef(),
        );

        $this->audit($request, 'iam.relation.granted', 'relation', $tuple->id, [
            'subject' => (string) $subject, 'relation' => $relation, 'object' => (string) $object,
        ]);

        return $this->ok([
            'id' => $tuple->id,
            'subject' => ['type' => $subject->type, 'id' => $subject->id],
            'relation' => $relation,
            'object' => ['type' => $object->type, 'id' => $object->id],
        ], 201);
    }

    public function destroy(Request $request): JsonResponse
    {
        [$subject, $relation, $object] = $this->parseTuple($request);
        $ctx = $this->context($request);

        $revoked = $this->writer->revoke($subject, $relation, $object, $ctx->organizationId);
        if ($revoked) {
            $this->audit($request, 'iam.relation.revoked', 'relation', null, [
                'subject' => (string) $subject, 'relation' => $relation, 'object' => (string) $object,
            ]);
        }

        return $this->ok(['revoked' => $revoked]);
    }

    /**
     * @return array{0: SubjectRef, 1: string, 2: ResourceRef}
     */
    private function parseTuple(Request $request): array
    {
        $subject = $request->input('subject');
        if (!is_array($subject) || !is_string($subject['id'] ?? null) || $subject['id'] === '') {
            throw ApiProblemException::unprocessable('Campo subject {type,id} obbligatorio.', ['subject' => ['subject.id è obbligatorio']]);
        }
        $relation = $request->input('relation');
        if (!is_string($relation) || $relation === '' || strlen($relation) > 255) {
            throw ApiProblemException::unprocessable('Campo relation obbligatorio (max 255).', ['relation' => ['relation è obbligatorio (max 255)']]);
        }
        $object = $request->input('object');
        if (!is_array($object) || !is_string($object['type'] ?? null) || !is_string($object['id'] ?? null) || $object['id'] === '') {
            throw ApiProblemException::unprocessable('Campo object {type,id} obbligatorio.', ['object' => ['object.type e object.id sono obbligatori']]);
        }

        $subjectType = is_string($subject['type'] ?? null) ? $subject['type'] : 'user';

        return [new SubjectRef($subjectType, $subject['id']), $relation, new ResourceRef($object['type'], $object['id'])];
    }

    /**
     * Normalizza un input (mixed) in una mappa a chiavi stringa, o null se non è un array.
     *
     * @return array<string, mixed>|null
     */
    private function stringKeyedArray(mixed $value): ?array
    {
        if (!is_array($value)) {
            return null;
        }
        $out = [];
        foreach ($value as $key => $item) {
            $out[(string) $key] = $item;
        }

        return $out;
    }
}
