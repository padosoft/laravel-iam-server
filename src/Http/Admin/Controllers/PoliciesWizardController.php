<?php

declare(strict_types=1);

namespace Padosoft\Iam\Http\Admin\Controllers;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Padosoft\Iam\Contracts\Authorization\AuthorizationEngine;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Iam\Domain\Authorization\Models\Grant;
use Padosoft\Iam\Domain\Authorization\Models\Permission;
use Padosoft\Iam\Domain\Authorization\Models\Role;
use Padosoft\Iam\Domain\Authorization\Pdp\NativeReBacResolver;
use Padosoft\Iam\Domain\Authorization\Pdp\ResourceRef;
use Padosoft\Iam\Http\Admin\AdminController;
use Padosoft\Iam\Http\Admin\Support\ApiProblemException;

/**
 * Admin API — Policy Wizard (doc 16 §3.14, doc 19 §6). SOLO controller: compone primitive esistenti per
 * una creazione guidata di grant. `preview` è read-mostly e NON scrive nulla (usa il PDP + list-subjects
 * M16 per l'anteprima d'impatto e i conflitti con deny esistenti); `commit` crea il grant in modo
 * idempotente con audit. Tenant-scoped; il commit richiede `iam:grants.manage`.
 */
final class PoliciesWizardController extends AdminController
{
    private const PRIVILEGE_TYPES = ['permission', 'role'];

    public function __construct(
        private readonly AuthorizationEngine $pdp,
        private readonly NativeReBacResolver $rebac,
    ) {}

    /**
     * Catalogo permessi/ruoli per comporre una policy (read-only). Filtrabile per app.
     */
    public function permissions(Request $request): JsonResponse
    {
        $app = $request->query('app');
        $app = is_string($app) && $app !== '' ? $app : null;

        $permissions = [];
        $permRows = Permission::query()
            ->whereNull('deprecated_at')
            ->when($app !== null, fn (Builder $q) => $q->where('app_key', $app))
            ->orderBy('full_key')->limit(500)->get();
        foreach ($permRows as $p) {
            $permissions[] = [
                'full_key' => $p->full_key,
                'app_key' => $p->getAttribute('app_key'), // Permission non annota app_key: accesso esplicito
                'risk' => $p->risk,
                'requires_step_up' => (bool) $p->requires_step_up,
            ];
        }

        $roles = [];
        $roleRows = Role::query()
            ->whereNull('deprecated_at')
            ->when($app !== null, fn (Builder $q) => $q->where('app_key', $app))
            ->orderBy('full_key')->limit(500)->get();
        foreach ($roleRows as $r) {
            $roles[] = ['full_key' => $r->full_key, 'app_key' => $r->app_key, 'label' => $r->label];
        }

        return $this->ok(['permissions' => $permissions, 'roles' => $roles]);
    }

    /**
     * Anteprima d'impatto di un grant proposto. NON scrive nulla: ritorna la decisione corrente del PDP
     * (allow/deny), chi otterrebbe accesso alla risorsa impattata (list-subjects M16, se relation+object
     * sono dati) e i conflitti con deny già esistenti per lo stesso soggetto/privilegio.
     */
    public function preview(Request $request): JsonResponse
    {
        $proposal = $this->parseProposal($request);
        $org = $this->context($request)->organizationId;

        // Decisione corrente (PRIMA del grant): mostra lo stato e cosa cambierebbe. Read-only.
        $current = $this->pdp->check([
            'subject' => ['type' => $proposal['subject_type'], 'id' => $proposal['subject_id']],
            'permission' => $proposal['privilege_type'] === 'permission' ? $proposal['privilege_key'] : '',
            'organization' => $org,
            'application' => $proposal['application_key'],
            'explain' => true,
        ]);

        // Impatto via list-subjects (M16): chi ha già accesso alla risorsa impattata (se relation+object).
        $currentHolders = [];
        if ($proposal['relation'] !== null && $proposal['object'] !== null) {
            foreach ($this->rebac->listSubjects($proposal['relation'], $proposal['object'], $org) as $subject) {
                $currentHolders[] = ['type' => $subject->type, 'id' => $subject->id];
            }
        }

        // Conflitti: deny attivi per lo stesso soggetto+privilegio (deny-overrides → il permit proposto
        // resterebbe inefficace finché il deny esiste).
        $conflicts = $this->conflictQuery($proposal, $org)->where('effect', 'deny')->active()->get()
            ->map(fn (Grant $g): array => ['id' => $g->id, 'effect' => $g->effect, 'privilege_key' => $g->privilege_key])->all();

        return $this->ok([
            'proposed' => $this->publicProposal($proposal),
            'writes' => false,
            'current_decision' => ['allowed' => (bool) ($current['allowed'] ?? false), 'explanation' => $current['explanation'] ?? []],
            'impact' => [
                'subject' => $proposal['subject_type'].':'.$proposal['subject_id'],
                'current_holders' => $currentHolders,
            ],
            'conflicts' => $conflicts,
        ]);
    }

    /**
     * Crea il grant proposto (idempotente sull'identità del grant). Un secondo commit identico ritorna il
     * grant esistente senza duplicare né ri-auditare.
     */
    public function commit(Request $request): JsonResponse
    {
        $proposal = $this->parseProposal($request);
        $org = $this->context($request)->organizationId;

        $existing = $this->conflictQuery($proposal, $org)->where('effect', $proposal['effect'])->first();
        if ($existing !== null) {
            return $this->ok($this->grantSummary($existing) + ['created' => false]);
        }

        try {
            $grant = Grant::create([
                'organization_id' => $org,
                'application_key' => $proposal['application_key'],
                'subject_type' => $proposal['subject_type'],
                'subject_id' => $proposal['subject_id'],
                'privilege_type' => $proposal['privilege_type'],
                'privilege_key' => $proposal['privilege_key'],
                'resource_ref' => $proposal['object'] !== null ? (string) $proposal['object'] : null,
                'effect' => $proposal['effect'],
                'source' => 'policy_wizard',
                'created_by' => $this->context($request)->actorRef(),
            ]);
        } catch (UniqueConstraintViolationException) {
            // Corsa: un commit concorrente ha vinto. Ritorna l'esistente (idempotenza preservata).
            $grant = $this->conflictQuery($proposal, $org)->where('effect', $proposal['effect'])->firstOrFail();

            return $this->ok($this->grantSummary($grant) + ['created' => false]);
        }

        $this->audit($request, 'iam.grant.created', 'grant', $grant->id, [
            'subject' => $proposal['subject_type'].':'.$proposal['subject_id'],
            'privilege' => $proposal['privilege_type'].':'.$proposal['privilege_key'],
        ]);

        return $this->ok($this->grantSummary($grant) + ['created' => true], 201);
    }

    /**
     * @param  array{subject_type: string, subject_id: string, privilege_type: string, privilege_key: string, application_key: string|null, effect: string, relation: string|null, object: ResourceRef|null}  $proposal
     * @return Builder<Grant>
     */
    private function conflictQuery(array $proposal, ?string $org): Builder
    {
        return Grant::query()
            ->where('subject_type', $proposal['subject_type'])
            ->where('subject_id', $proposal['subject_id'])
            ->where('privilege_type', $proposal['privilege_type'])
            ->where('privilege_key', $proposal['privilege_key'])
            ->when($org !== null, fn (Builder $q) => $q->where('organization_id', $org), fn (Builder $q) => $q->whereNull('organization_id'))
            ->when($proposal['application_key'] !== null, fn (Builder $q) => $q->where('application_key', $proposal['application_key']));
    }

    /**
     * @return array{subject_type: string, subject_id: string, privilege_type: string, privilege_key: string, application_key: string|null, effect: string, relation: string|null, object: ResourceRef|null}
     */
    private function parseProposal(Request $request): array
    {
        $subject = $request->input('subject');
        if (!is_array($subject) || !is_string($subject['id'] ?? null) || $subject['id'] === '') {
            throw ApiProblemException::unprocessable('Campo subject {type,id} obbligatorio.', ['subject' => ['subject.id è obbligatorio']]);
        }
        $privilegeType = $request->input('privilege_type');
        if (!is_string($privilegeType) || !in_array($privilegeType, self::PRIVILEGE_TYPES, true)) {
            throw ApiProblemException::unprocessable('Campo privilege_type obbligatorio (permission|role).', ['privilege_type' => ['privilege_type non valido']]);
        }
        $privilegeKey = $request->input('privilege_key');
        if (!is_string($privilegeKey) || $privilegeKey === '' || strlen($privilegeKey) > 255) {
            throw ApiProblemException::unprocessable('Campo privilege_key obbligatorio (max 255).', ['privilege_key' => ['privilege_key è obbligatorio']]);
        }

        $effect = $request->input('effect');
        $effect = $effect === 'deny' ? 'deny' : 'permit';

        $application = $request->input('application');
        $relation = $request->input('relation');
        $object = $request->input('object');

        return [
            'subject_type' => is_string($subject['type'] ?? null) ? $subject['type'] : 'user',
            'subject_id' => $subject['id'],
            'privilege_type' => $privilegeType,
            'privilege_key' => $privilegeKey,
            'application_key' => is_string($application) && $application !== '' ? $application : null,
            'effect' => $effect,
            'relation' => is_string($relation) && $relation !== '' ? $relation : null,
            'object' => is_array($object) && is_string($object['type'] ?? null) && is_string($object['id'] ?? null) && $object['id'] !== ''
                ? new ResourceRef($object['type'], $object['id'])
                : null,
        ];
    }

    /**
     * @param  array{subject_type: string, subject_id: string, privilege_type: string, privilege_key: string, application_key: string|null, effect: string, relation: string|null, object: ResourceRef|null}  $proposal
     * @return array<string, mixed>
     */
    private function publicProposal(array $proposal): array
    {
        return [
            'subject' => (string) new SubjectRef($proposal['subject_type'], $proposal['subject_id']),
            'privilege_type' => $proposal['privilege_type'],
            'privilege_key' => $proposal['privilege_key'],
            'application_key' => $proposal['application_key'],
            'effect' => $proposal['effect'],
            'object' => $proposal['object'] !== null ? (string) $proposal['object'] : null,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function grantSummary(Grant $g): array
    {
        return [
            'id' => $g->id, 'subject' => $g->subject_type.':'.$g->subject_id,
            'privilege_type' => $g->privilege_type, 'privilege_key' => $g->privilege_key,
            'effect' => $g->effect, 'application_key' => $g->application_key,
            'resource_ref' => $g->resource_ref, 'organization_id' => $g->organization_id,
        ];
    }
}
