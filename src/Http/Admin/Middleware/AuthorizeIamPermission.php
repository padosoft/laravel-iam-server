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
        ]);

        if (($decision['allowed'] ?? false) !== true) {
            throw ApiProblemException::forbidden("Permesso {$permission} negato.");
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
