<?php

declare(strict_types=1);

namespace Padosoft\Iam\Http\Admin\Support;

use Illuminate\Http\Request;

/**
 * Risolve l'identità del chiamante dell'Admin API da una richiesta HTTP (doc 16 §6). Astratto così
 * il meccanismo (bearer JWT IAM, introspection, widget token) è sostituibile senza toccare i
 * controller. Ritorna null se la richiesta non è autenticata → il middleware risponde 401.
 */
interface AdminActorResolver
{
    public function resolve(Request $request): ?AdminContext;
}
