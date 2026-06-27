<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Governance\Requests;

use Padosoft\Iam\Contracts\Governance\FeatureContext;
use Padosoft\Iam\Contracts\Governance\FeatureKey;
use Padosoft\Iam\Contracts\Governance\FeatureScope;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Iam\Domain\Authorization\Models\Role;
use Padosoft\Iam\Domain\Organizations\Models\Membership;

/**
 * Catalogo self-service (doc 14 §4) — DEFAULT-DENY. Espone solo i ruoli che il richiedente può
 * davvero vedere/richiedere, dopo TRE cancelli combinati (ADR-AReq-001):
 *   1. FeatureScope.access_request ACCESO per app/ruolo;
 *   2. il richiedente possiede il permesso d'uso (iam:access_request.use);
 *   3. il ruolo è `self_requestable` nel manifest E supera la sua visibility policy.
 * Se uno qualunque manca → il ruolo NON compare (nessuno scopre app/ruoli non concessi).
 */
final class RequestCatalog
{
    public function __construct(private readonly FeatureScope $features) {}

    /**
     * Ruoli visibili e richiedibili dal soggetto. `$organizationId` è il contesto org della richiesta
     * (usato dalla visibility policy `members_of_org` e dal gate FeatureScope).
     *
     * @return list<Role>
     */
    public function visibleRoles(SubjectRef $requester, ?string $organizationId = null, ?string $applicationKey = null): array
    {
        // Gate 2 (a monte): senza il permesso d'uso, il catalogo è interamente vuoto.
        $useCtx = new FeatureContext(
            feature: FeatureKey::AccessRequest,
            organizationId: $organizationId,
            applicationKey: $applicationKey,
        );
        if (!$this->features->isPermitted($useCtx, $requester)) {
            return [];
        }

        $query = Role::query()
            ->where('self_requestable', true)
            ->whereNull('deprecated_at');
        if ($applicationKey !== null) {
            $query->where('app_key', $applicationKey);
        }

        $visible = [];
        foreach ($query->get() as $role) {
            if ($this->isVisible($role, $requester, $organizationId)) {
                $visible[] = $role;
            }
        }

        return $visible;
    }

    /** Un singolo ruolo è visibile/richiedibile dal soggetto? (stessi tre cancelli). */
    public function canRequest(Role $role, SubjectRef $requester, ?string $organizationId = null): bool
    {
        if (!$role->self_requestable || $role->deprecated_at !== null) {
            return false;
        }
        $useCtx = new FeatureContext(
            feature: FeatureKey::AccessRequest,
            organizationId: $organizationId,
            applicationKey: $role->app_key,
        );
        if (!$this->features->isPermitted($useCtx, $requester)) {
            return false;
        }

        return $this->isVisible($role, $requester, $organizationId);
    }

    /** Gate 1 (FeatureScope acceso per app/ruolo) + Gate 3b (visibility policy). */
    private function isVisible(Role $role, SubjectRef $requester, ?string $organizationId): bool
    {
        $ctx = new FeatureContext(
            feature: FeatureKey::AccessRequest,
            organizationId: $organizationId,
            applicationKey: $role->app_key,
            roleKey: $role->full_key,
        );
        if (!$this->features->isEnabled($ctx)) {
            return false;
        }

        return $this->passesVisibility($role, $requester, $organizationId);
    }

    /**
     * Visibility policy del ruolo (default-deny): una policy assente o sconosciuta NON rende il ruolo
     * visibile. v1 implementa `public` (chiunque abbia passato i gate 1+2) e `members_of_org` (solo
     * membri attivi dell'org). Policy custom → estendibili qui senza toccare i chiamanti.
     */
    private function passesVisibility(Role $role, SubjectRef $requester, ?string $organizationId): bool
    {
        $request = $role->request_json ?? [];
        $visibility = is_array($request['visibility'] ?? null) ? $request['visibility'] : [];
        $policy = is_string($visibility['policy'] ?? null) ? $visibility['policy'] : null;

        return match ($policy) {
            'public' => true,
            'members_of_org' => $this->isActiveMember($requester, $organizationId),
            default => false, // fail-closed: nessuna policy esplicita riconosciuta → non visibile
        };
    }

    private function isActiveMember(SubjectRef $requester, ?string $organizationId): bool
    {
        // Fail-closed: `members_of_org` richiede un'org CONCRETA. Senza (catalogo globale, org null)
        // non si può verificare l'appartenenza a una specifica org → non visibile, altrimenti un
        // membro di una qualunque org vedrebbe ruoli members_of_org di org a cui non appartiene.
        if ($requester->type !== 'user' || $organizationId === null) {
            return false;
        }

        return Membership::query()
            ->where('user_id', $requester->id)
            ->where('organization_id', $organizationId)
            ->where('status', 'active')
            ->exists();
    }
}
