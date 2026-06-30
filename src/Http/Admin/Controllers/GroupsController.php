<?php

declare(strict_types=1);

namespace Padosoft\Iam\Http\Admin\Controllers;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Padosoft\Iam\Domain\Groups\GroupMembershipService;
use Padosoft\Iam\Domain\Groups\Models\Group;
use Padosoft\Iam\Domain\Groups\Models\GroupMember;
use Padosoft\Iam\Http\Admin\AdminController;
use Padosoft\Iam\Http\Admin\Support\ApiProblemException;

/**
 * Admin API — Groups (doc 16 §3.4, doc 19 §3). Gruppi first-class (soggetti di grant/ReBAC) con CRUD e
 * gestione membri. Ogni membership passa dal GroupMembershipService che scrive ANCHE la tupla ReBAC
 * `member`, così il motore nativo (M16) vede il nesting. Tenant-scoped (cross-tenant = 404); audit per
 * mutazione.
 */
final class GroupsController extends AdminController
{
    /** Tipi di membro ammessi (= subject_type ReBAC). */
    private const MEMBER_TYPES = ['user', 'group', 'service_account'];

    public function __construct(private readonly GroupMembershipService $memberships) {}

    public function index(Request $request): JsonResponse
    {
        $query = Group::query();
        $org = $this->context($request)->organizationId;
        if ($org !== null) {
            $query->where('organization_id', $org);
        }

        return $this->paginate($query, $request, fn (Model $g): array => $g instanceof Group ? $this->summary($g) : []);
    }

    public function store(Request $request): JsonResponse
    {
        $key = $this->requiredString($request, 'key');
        $name = $this->requiredString($request, 'name');
        $source = $request->input('source');
        $org = $this->context($request)->organizationId;
        if ($org === null) {
            // Un gruppo è sempre tenant-scoped: senza un'org effettiva non si può creare in modo sicuro.
            throw ApiProblemException::unprocessable('organization obbligatoria per creare un gruppo.');
        }

        // Create diretto: l'unique (organization_id, key) è applicato dal DB → un duplicato è 409,
        // non una 500 (no TOCTOU: la corsa è arbitrata dal constraint).
        try {
            $group = Group::create([
                'organization_id' => $org,
                'key' => $key,
                'name' => $name,
                'source' => is_string($source) && $source !== '' ? $source : 'manual',
            ]);
        } catch (UniqueConstraintViolationException) {
            throw ApiProblemException::conflict("Gruppo con key \"{$key}\" già esistente in questa organizzazione.");
        }

        $this->audit($request, 'iam.group.created', 'group', $group->id, ['key' => $key]);

        return $this->ok($this->summary($group), 201);
    }

    public function show(Request $request, string $group): JsonResponse
    {
        return $this->ok($this->summary($this->find($request, $group)));
    }

    public function update(Request $request, string $group): JsonResponse
    {
        $model = $this->find($request, $group);
        $before = $this->summary($model);

        $name = $request->input('name');
        if (is_string($name) && $name !== '') {
            $model->name = $name;
        }
        $source = $request->input('source');
        if (is_string($source) && $source !== '') {
            $model->source = $source;
        }
        $model->save();

        $this->audit($request, 'iam.group.updated', 'group', $model->id, [], $before, $this->summary($model));

        return $this->ok($this->summary($model));
    }

    public function destroy(Request $request, string $group): JsonResponse
    {
        $model = $this->find($request, $group);
        if ($model->revoked_at !== null) {
            throw ApiProblemException::conflict('Gruppo già revocato.');
        }
        $model->revoke();
        $this->audit($request, 'iam.group.deleted', 'group', $model->id, []);

        return $this->ok(['id' => $model->id, 'revoked' => true]);
    }

    public function members(Request $request, string $group): JsonResponse
    {
        $model = $this->find($request, $group);

        return $this->paginate(
            $this->memberships->membersQuery($model),
            $request,
            fn (Model $m): array => $m instanceof GroupMember ? $this->memberSummary($m) : [],
        );
    }

    public function addMember(Request $request, string $group): JsonResponse
    {
        $model = $this->find($request, $group);
        [$type, $id] = $this->parseMember($request);

        $member = $this->memberships->addMember($model, $type, $id, $this->context($request)->actorRef());
        $this->audit($request, 'iam.group.member_added', 'group', $model->id, ['member' => $type.':'.$id]);

        return $this->ok($this->memberSummary($member), 201);
    }

    public function removeMember(Request $request, string $group): JsonResponse
    {
        $model = $this->find($request, $group);
        [$type, $id] = $this->parseMember($request);

        $removed = $this->memberships->removeMember($model, $type, $id);
        if ($removed) {
            $this->audit($request, 'iam.group.member_removed', 'group', $model->id, ['member' => $type.':'.$id]);
        }

        return $this->ok(['removed' => $removed]);
    }

    private function find(Request $request, string $group): Group
    {
        $org = $this->context($request)->organizationId;
        $model = Group::query()->where('key', $group)->first() ?? Group::query()->find($group);
        if ($model === null || ($org !== null && $model->organization_id !== $org)) {
            throw ApiProblemException::notFound("Gruppo \"{$group}\" non trovato.");
        }

        return $model;
    }

    /**
     * @return array{0: string, 1: string}
     */
    private function parseMember(Request $request): array
    {
        $type = $request->input('member_type');
        if (!is_string($type) || !in_array($type, self::MEMBER_TYPES, true)) {
            throw ApiProblemException::unprocessable('Campo member_type obbligatorio (user|group|service_account).', ['member_type' => ['member_type non valido']]);
        }
        $id = $request->input('member_id');
        if (!is_string($id) || $id === '' || strlen($id) > 255) {
            throw ApiProblemException::unprocessable('Campo member_id obbligatorio (max 255).', ['member_id' => ['member_id è obbligatorio']]);
        }

        return [$type, $id];
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
    private function summary(Group $g): array
    {
        return [
            'id' => $g->id, 'key' => $g->key, 'name' => $g->name, 'source' => $g->source,
            'organization_id' => $g->organization_id,
            'revoked_at' => $g->revoked_at?->toIso8601String(),
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function memberSummary(GroupMember $m): array
    {
        return [
            'id' => $m->id, 'group_id' => $m->group_id,
            'member_type' => $m->member_type, 'member_id' => $m->member_id,
        ];
    }
}
