<?php

declare(strict_types=1);

namespace Padosoft\Iam\Http\Admin\Middleware;

use Closure;
use Illuminate\Http\Request;
use Padosoft\Iam\Http\Admin\Support\AdminActorResolver;
use Padosoft\Iam\Http\Admin\Support\AdminContext;
use Padosoft\Iam\Http\Admin\Support\ApiProblemException;
use Symfony\Component\HttpFoundation\Response;

/**
 * Autentica una richiesta Admin API (doc 16 §6). Risolve l'attore via AdminActorResolver e lo
 * deposita negli attributi della richiesta (`iam_admin_context`) per i middleware/controller a valle.
 * Fail-closed: senza un'identità valida → 401 problem+json.
 */
final class AdminAuthenticate
{
    public function __construct(private readonly AdminActorResolver $resolver) {}

    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $context = $this->resolver->resolve($request);
        if (!$context instanceof AdminContext) {
            throw ApiProblemException::unauthorized();
        }

        $request->attributes->set('iam_admin_context', $context);

        return $next($request);
    }
}
