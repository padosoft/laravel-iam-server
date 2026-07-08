<?php

declare(strict_types=1);

namespace Padosoft\Iam\Http\Admin\Middleware;

use Closure;
use Illuminate\Http\Request;
use Padosoft\Iam\Contracts\Authorization\AuthorizationEngine;
use Padosoft\Iam\Http\Admin\Support\AdminContext;
use Padosoft\Iam\Http\Admin\Support\ApiProblemException;
use Symfony\Component\HttpFoundation\Response;

/**
 * Gate di permesso dell'Admin API (doc 16 §6): ogni endpoint dichiara il permesso richiesto e il PDP
 * è l'autorità (la UI è solo un suggerimento). FAIL-CLOSED: senza contesto autenticato o senza una
 * decisione `allow` esplicita → 403. Tenant scoping: l'org è quella del query param `organization`,
 * ma deve combaciare con l'org del token quando questo è vincolato a un tenant (no cross-tenant).
 *
 * Uso: ->middleware('iam.can:iam:users.read')
 */
final class AuthorizeIamPermission
{
    public function __construct(private readonly AuthorizationEngine $pdp) {}

    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next, string $permission): Response
    {
        $context = $request->attributes->get('iam_admin_context');
        if (!$context instanceof AdminContext) {
            // AdminAuthenticate deve precedere: assenza di contesto = mai autenticato → fail-closed.
            throw ApiProblemException::unauthorized();
        }

        $organizationId = $this->resolveOrganization($request, $context);

        $decision = $this->pdp->check([
            'subject' => ['type' => $context->actor->type, 'id' => $context->actor->id],
            'permission' => $permission,
            'organization' => $organizationId,
            // IAM-04: thread the actor's real AAL so the PDP can decide whether this permission needs
            // step-up. Without it the PDP defaults to aal1 and stamps requires_step_up, which we then
            // enforce below.
            'current_aal' => $context->aal,
        ]);

        if (($decision['allowed'] ?? false) !== true) {
            throw ApiProblemException::forbidden("Permesso {$permission} negato.");
        }

        // IAM-04: `granted`, not bare `allowed`, is the truth. A permit that still requires step-up
        // (the actor's AAL is below the permission's required level) must NOT proceed — enforce the
        // ecosystem's granted() = allowed && !requires_step_up invariant instead of the "allowed nudo"
        // anti-pattern. Signal the required AAL so the caller can re-authenticate (step-up).
        if (($decision['requires_step_up'] ?? false) === true) {
            $requiredAal = $decision['required_aal'] ?? null;
            throw ApiProblemException::stepUpRequired(is_string($requiredAal) ? $requiredAal : 'aal2');
        }

        // IAM-01: single source of truth for tenant scope. The gate authorized the permission against
        // `$organizationId`; the controller/PDP/audit data layer must scope to the SAME org, never a wider
        // one. When an unbound (null-org) token explicitly targets a tenant via `?organization=`, bind the
        // admin context to that resolved org for the rest of the request so `context->organizationId`
        // downstream equals what we authorized. The genuine see-all-tenants path stays gated: a null
        // effective org only matches `organization_id IS NULL` (global) grants in the PDP, so an
        // org-scoped grant plus a query param can never widen the data scope to global.
        if ($context->organizationId === null && $organizationId !== null) {
            $request->attributes->set('iam_admin_context', new AdminContext(
                actor: $context->actor,
                organizationId: $organizationId,
                scopes: $context->scopes,
                aal: $context->aal,
            ));
        }

        return $next($request);
    }

    /**
     * Org effettiva della richiesta. Se il token è vincolato a un tenant, un `organization` diverso
     * nel query param è un tentativo cross-tenant → 403 (no escalation orizzontale).
     */
    private function resolveOrganization(Request $request, AdminContext $context): ?string
    {
        $requested = $request->query('organization');
        $requested = is_string($requested) && $requested !== '' ? $requested : null;

        if ($context->organizationId !== null && $requested !== null && $requested !== $context->organizationId) {
            throw ApiProblemException::forbidden();
        }

        return $context->organizationId ?? $requested;
    }
}
