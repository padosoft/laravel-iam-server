<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Authorization\Pdp;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Collection;
use Illuminate\Support\Str;
use Padosoft\Iam\Contracts\Authorization\AuthorizationEngine;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Iam\Domain\Authorization\Models\Grant;
use Padosoft\Iam\Domain\Authorization\Models\Permission;
use Padosoft\Iam\Domain\Authorization\Models\Role;
use Padosoft\Iam\Domain\Governance\GrantUsageRecorder;
use Padosoft\Iam\Domain\Organizations\Models\Organization;

/**
 * PDP nativo su SQL: RBAC + ABAC con algoritmo deny-overrides + default-deny (doc 09 §4).
 * Il ReBAC (relation/list-*) arriva con il reverse-index in M2.x/v2.
 */
final class NativeSqlEngine implements AuthorizationEngine
{
    public function __construct(
        private readonly ConditionEvaluator $conditions = new ConditionEvaluator,
        private readonly ?GrantUsageRecorder $usage = null,
    ) {}

    public function decide(DecisionQuery $q): Decision
    {
        $explain = [];
        $policyVersion = $this->policyVersion($q->organizationId);
        $decisionId = 'dec_'.Str::ulid()->toBase32();

        /** @var list<Grant> $denies */
        $denies = [];
        /** @var list<Grant> $permits */
        $permits = [];

        foreach ($this->subjectGrants($q) as $grant) {
            if (!$this->grantsPermission($grant, $q->permission)) {
                continue;
            }
            // Scope: grant senza resource_ref vale ovunque; altrimenti deve combaciare.
            if ($grant->resource_ref !== null && $grant->resource_ref !== $q->resourceRef) {
                continue;
            }
            $conds = $grant->conditions_json ?? [];
            $failed = $this->conditions->failed($conds, $q->context);
            if ($failed !== []) {
                $explain[] = "Grant {$grant->id} ({$grant->privilege_key}) saltato: condizioni non soddisfatte: ".implode('; ', $failed);

                continue;
            }
            $grant->effect === 'deny' ? $denies[] = $grant : $permits[] = $grant;
        }

        // deny-overrides
        if ($denies !== []) {
            $g = $denies[0];

            return new Decision(
                allowed: false,
                decisionId: $decisionId,
                policyVersion: $policyVersion,
                matched: [['type' => 'deny', 'key' => $g->privilege_key]],
                explanation: [...$explain, "DENY esplicito da grant {$g->id} ({$g->privilege_key}) — deny-overrides."],
            );
        }

        // default-deny (fail-closed)
        if ($permits === []) {
            return new Decision(
                allowed: false,
                decisionId: $decisionId,
                policyVersion: $policyVersion,
                explanation: [...$explain, "Nessun permit valido per {$q->permission} → default-deny (fail-closed)."],
            );
        }

        // permit (+ eventuale step-up)
        $g = $permits[0];
        // Usage capture (doc 14 §2): segnala il grant che ha prodotto il permit → last_used_at (batch).
        ($this->usage ?? app(GrantUsageRecorder::class))->record($g->id);
        $requiresStepUp = $this->requiresStepUp($q->permission) && !$this->aalSufficient($q->currentAal, 'aal2');
        $explain[] = "PERMIT da grant {$g->id} ({$g->privilege_type}:{$g->privilege_key}) per {$q->permission}.";
        if ($requiresStepUp) {
            $explain[] = "Permesso {$q->permission} richiede step-up: AAL {$q->currentAal} < aal2.";
        }

        return new Decision(
            allowed: true,
            decisionId: $decisionId,
            policyVersion: $policyVersion,
            requiresStepUp: $requiresStepUp,
            requiredAal: $requiresStepUp ? 'aal2' : null,
            matched: [['type' => $g->privilege_type, 'key' => $g->privilege_key]],
            explanation: $explain,
        );
    }

    /** @return Collection<int, Grant> */
    private function subjectGrants(DecisionQuery $q): Collection
    {
        // Fail-closed: i filtri org/app sono SEMPRE applicati. Se la query non specifica
        // org/app, `orWhere(col, null)` diventa `col IS NULL` → matchano solo i grant
        // globali, mai quelli scoped di un altro tenant/app (no cross-tenant/app escalation).
        return Grant::query()->active()
            ->where('subject_type', $q->subject->type)
            ->where('subject_id', $q->subject->id)
            ->where(fn (Builder $w) => $w->whereNull('organization_id')->orWhere('organization_id', $q->organizationId))
            ->where(fn (Builder $w) => $w->whereNull('application_key')->orWhere('application_key', $q->applicationKey))
            ->get();
    }

    private function grantsPermission(Grant $grant, string $permissionFullKey): bool
    {
        return match ($grant->privilege_type) {
            'permission' => $grant->privilege_key === $permissionFullKey && !$this->permissionDeprecated($permissionFullKey),
            'role' => Role::query()
                ->where('full_key', $grant->privilege_key)
                ->whereNull('deprecated_at')
                ->whereHas('permissions', fn (Builder $b) => $b->where('full_key', $permissionFullKey)->whereNull('deprecated_at'))
                ->exists(),
            default => false, // relation → ReBAC (M2.x)
        };
    }

    private function permissionDeprecated(string $fullKey): bool
    {
        return Permission::query()->where('full_key', $fullKey)->whereNotNull('deprecated_at')->exists();
    }

    private function requiresStepUp(string $permissionFullKey): bool
    {
        return Permission::query()
            ->where('full_key', $permissionFullKey)
            ->where('requires_step_up', true)
            ->exists();
    }

    private function aalSufficient(string $current, string $required): bool
    {
        $rank = ['aal1' => 1, 'aal2' => 2, 'aal3' => 3];

        return ($rank[$current] ?? 0) >= ($rank[$required] ?? 99);
    }

    private function policyVersion(?string $organizationId): int
    {
        if ($organizationId === null) {
            return 0;
        }
        $value = Organization::query()->whereKey($organizationId)->value('policy_version');

        return is_numeric($value) ? (int) $value : 0;
    }

    // --- Contract AuthorizationEngine ---

    public function check(array $query): array
    {
        $subject = is_array($query['subject'] ?? null) ? $query['subject'] : [];
        $context = is_array($query['context'] ?? null) ? $query['context'] : [];
        /** @var array<string, mixed> $context */
        $q = new DecisionQuery(
            subject: new SubjectRef($this->str($subject['type'] ?? null, 'user'), $this->str($subject['id'] ?? null)),
            permission: $this->str($query['permission'] ?? null),
            organizationId: isset($query['organization']) ? $this->str($query['organization']) : null,
            applicationKey: isset($query['application']) ? $this->str($query['application']) : null,
            resourceRef: isset($query['resource']) ? $this->str($query['resource']) : null,
            context: $context,
            currentAal: $this->str($query['current_aal'] ?? null, 'aal1'),
            explain: (bool) ($query['explain'] ?? false),
        );

        return $this->decide($q)->toArray();
    }

    private function str(mixed $value, string $default = ''): string
    {
        return is_scalar($value) ? (string) $value : $default;
    }

    public function listSubjects(string $relation, string $objectType, string $objectId): iterable
    {
        throw new \RuntimeException('list-subjects: disponibile con il ReBAC reverse-index (M2.x/v2).');
    }

    public function listResources(SubjectRef $subject, string $relation): iterable
    {
        throw new \RuntimeException('list-resources: disponibile con il ReBAC reverse-index (M2.x/v2).');
    }
}
