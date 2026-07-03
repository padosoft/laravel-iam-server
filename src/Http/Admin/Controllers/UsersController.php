<?php

declare(strict_types=1);

namespace Padosoft\Iam\Http\Admin\Controllers;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Padosoft\Iam\Domain\Authorization\Models\Grant;
use Padosoft\Iam\Domain\Authorization\Models\Role;
use Padosoft\Iam\Domain\Identity\Models\User;
use Padosoft\Iam\Domain\Organizations\Models\Membership;
use Padosoft\Iam\Http\Admin\AdminController;
use Padosoft\Iam\Http\Admin\Support\ApiProblemException;

/**
 * Admin API — Users (doc 16 §3.2). Lettura (lista/dettaglio/permessi effettivi) e azioni di
 * lifecycle (suspend/reactivate). Ogni mutazione passa dal mutator controllato del model
 * (`changeStatus`, audit garantito) e da audit admin con l'attore.
 */
final class UsersController extends AdminController
{
    public function index(Request $request): JsonResponse
    {
        $query = User::query();

        // Tenant scoping (doc 16 §6): un admin vincolato a un'org vede SOLO i membri di quell'org.
        $org = $this->context($request)->organizationId;
        if ($org !== null) {
            $query->whereIn('id', Membership::query()->where('organization_id', $org)->select('user_id'));
        }

        $status = $request->query('filter');
        if (is_array($status) && is_string($status['status'] ?? null) && $status['status'] !== '') {
            $query->where('status', $status['status']);
        }

        // Free-text search over name/email (console user picker). LIKE with escaped wildcards.
        $q = $request->query('q');
        if (is_string($q) && trim($q) !== '') {
            $needle = '%'.addcslashes(trim($q), '%_\\').'%';
            $query->where(function (Builder $w) use ($needle): void {
                $w->where('name', 'like', $needle)->orWhere('email', 'like', $needle);
            });
        }

        return $this->paginate(
            $query,
            $request,
            fn (Model $u): array => $u instanceof User ? $this->summary($u, $org) : [],
        );
    }

    public function update(Request $request, string $user): JsonResponse
    {
        $model = $this->find($user, $this->context($request)->organizationId);

        $changes = [];
        $errors = [];

        $name = $request->input('name');
        if ($name !== null) {
            if (!is_string($name) || trim($name) === '' || mb_strlen($name) > 255) {
                $errors['name'] = ['name deve essere una stringa non vuota (max 255).'];
            } else {
                $changes['name'] = $name;
            }
        }

        $email = $request->input('email');
        if ($email !== null) {
            // Normalize like the login/registration path (Fortify lowercases usernames) so a collation-
            // sensitive DB can't drift the uniqueness check / login lookup.
            $normalized = is_string($email) ? Str::lower(trim($email)) : null;
            if ($normalized === null || $normalized === '' || mb_strlen($normalized) > 255 || filter_var($normalized, FILTER_VALIDATE_EMAIL) === false) {
                $errors['email'] = ['email non valida.'];
            } elseif (User::query()->where('email', $normalized)->whereKeyNot($model->getKey())->exists()) {
                $errors['email'] = ['email già in uso.'];
            } else {
                $changes['email'] = $normalized;
            }
        }

        if ($errors !== []) {
            throw ApiProblemException::unprocessable('Payload non valido.', $errors);
        }
        if ($changes === []) {
            throw ApiProblemException::unprocessable('Nessun campo da aggiornare (name/email).');
        }

        $before = ['name' => $model->name, 'email' => $model->email];
        try {
            $model->fill($changes)->save();
        } catch (UniqueConstraintViolationException) {
            // A concurrent write took the email between the check and the save → clean 422, not a 500.
            throw ApiProblemException::unprocessable('Payload non valido.', ['email' => ['email già in uso.']]);
        }
        $this->audit($request, 'iam.user.updated', 'user', $user, [], $before, $changes);

        return $this->ok($this->summary($model->fresh() ?? $model, $this->context($request)->organizationId));
    }

    public function grants(Request $request, string $user): JsonResponse
    {
        $org = $this->context($request)->organizationId;
        $this->find($user, $org); // 404 se inesistente / fuori dal tenant

        $grants = Grant::query()->active()
            ->where('subject_type', 'user')
            ->where('subject_id', $user)
            ->when($org !== null, fn ($q) => $q->where(fn ($w) => $w->whereNull('organization_id')->orWhere('organization_id', $org)))
            ->orderBy('privilege_type')
            ->orderBy('privilege_key')
            ->get();

        return $this->ok([
            'user_id' => $user,
            'grants' => $grants->map(fn (Grant $g): array => [
                'id' => $g->id,
                'privilege_type' => $g->privilege_type,
                'privilege_key' => $g->privilege_key,
                'effect' => $g->effect,
                'application_key' => $g->application_key,
                'is_privileged' => $g->is_privileged,
                'valid_until' => $g->valid_until?->toIso8601String(),
                'source' => $g->source,
            ])->all(),
        ]);
    }

    public function show(Request $request, string $user): JsonResponse
    {
        $org = $this->context($request)->organizationId;

        return $this->ok($this->summary($this->find($user, $org), $org));
    }

    public function effectivePermissions(Request $request, string $user): JsonResponse
    {
        $org = $this->context($request)->organizationId;
        $this->find($user, $org); // 404 se inesistente / fuori dal tenant

        $grants = Grant::query()->active()
            ->where('subject_type', 'user')
            ->where('subject_id', $user)
            // Tenant scoping: un admin di un'org vede solo i grant di quell'org (+ globali), mai quelli
            // scoped di un altro tenant per lo stesso soggetto (no disclosure cross-tenant).
            ->when($org !== null, fn ($q) => $q->where(fn ($w) => $w->whereNull('organization_id')->orWhere('organization_id', $org)))
            ->get();

        $permissions = [];
        foreach ($grants as $grant) {
            if ($grant->privilege_type === 'permission') {
                $permissions[$grant->privilege_key] = ['via' => 'direct', 'grant_id' => $grant->id];
            } elseif ($grant->privilege_type === 'role') {
                foreach ($this->rolePermissions($grant->privilege_key) as $permKey) {
                    $permissions[$permKey] = ['via' => 'role:'.$grant->privilege_key, 'grant_id' => $grant->id];
                }
            }
        }

        return $this->ok(['user_id' => $user, 'permissions' => $permissions]);
    }

    public function suspend(Request $request, string $user): JsonResponse
    {
        $model = $this->find($user, $this->context($request)->organizationId);
        if ($model->status === 'suspended') {
            throw ApiProblemException::conflict('Utente già sospeso.');
        }
        $reason = $request->input('reason');
        $model->changeStatus('suspended', $this->context($request)->actorRef(), is_string($reason) ? $reason : '', 'admin-api');

        $this->audit($request, 'iam.user.suspended', 'user', $user, ['reason' => is_string($reason) ? $reason : null], ['status' => 'active'], ['status' => 'suspended']);

        return $this->ok($this->summary($model->fresh() ?? $model, $this->context($request)->organizationId));
    }

    public function reactivate(Request $request, string $user): JsonResponse
    {
        $model = $this->find($user, $this->context($request)->organizationId);
        if ($model->status === 'active') {
            throw ApiProblemException::conflict('Utente già attivo.');
        }
        $before = $model->status;
        $model->changeStatus('active', $this->context($request)->actorRef(), '', 'admin-api');

        $this->audit($request, 'iam.user.reactivated', 'user', $user, [], ['status' => $before], ['status' => 'active']);

        return $this->ok($this->summary($model->fresh() ?? $model, $this->context($request)->organizationId));
    }

    private function find(string $user, ?string $org = null): User
    {
        $model = User::query()->find($user);
        // Tenant scoping: per un admin vincolato a un'org, un utente non membro di quell'org è
        // indistinguibile da uno inesistente (stesso 404) → niente enumerazione cross-tenant di UUID.
        if ($model === null || ($org !== null && !$this->isMember($user, $org))) {
            throw ApiProblemException::notFound("Utente \"{$user}\" non trovato.");
        }

        return $model;
    }

    private function isMember(string $userId, string $org): bool
    {
        return Membership::query()->where('user_id', $userId)->where('organization_id', $org)->exists();
    }

    /**
     * @return array<string, mixed>
     */
    private function summary(User $u, ?string $org = null): array
    {
        $createdAt = $u->getAttribute('created_at');

        // Active role grants held by the user (privilege_key = role full_key). Honors validity/PIM via
        // active() and is tenant-scoped exactly like effectivePermissions() — never surfaces another
        // tenant's role grants. The console derives the super-admin badge from this list (iam-admin role).
        $roles = Grant::query()->active()
            ->where('subject_type', 'user')
            ->where('subject_id', $u->id)
            ->where('privilege_type', 'role')
            ->when($org !== null, fn ($q) => $q->where(fn ($w) => $w->whereNull('organization_id')->orWhere('organization_id', $org)))
            ->pluck('privilege_key')
            ->values()
            ->all();

        return [
            'id' => $u->id,
            'email' => $u->email,
            'name' => $u->name,
            'status' => $u->status,
            'roles' => array_values(array_filter($roles, 'is_string')),
            'created_at' => $createdAt instanceof \DateTimeInterface ? $createdAt->format(\DateTimeInterface::ATOM) : null,
        ];
    }

    /**
     * @return list<string>
     */
    private function rolePermissions(string $roleFullKey): array
    {
        $role = Role::query()->where('full_key', $roleFullKey)->whereNull('deprecated_at')->first();
        if ($role === null) {
            return [];
        }

        return array_values(array_filter(
            $role->permissions()->whereNull('deprecated_at')->pluck('full_key')->all(),
            'is_string',
        ));
    }
}
