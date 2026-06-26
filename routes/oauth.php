<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Padosoft\Iam\Http\Controllers\OAuth\AuthorizeController;
use Padosoft\Iam\Http\Controllers\OAuth\TokenController;

/*
 * Endpoint OAuth2 / OIDC (doc 13 §7). Il prefix è configurabile (iam.oauth.route_prefix).
 * Le rotte si arricchiscono per slice:
 *  - M4b.1: POST /token (client_credentials)
 *  - M4b.2: GET /authorize (authorization_code + PKCE)
 *  - M4b.5: POST /introspect, POST /revoke
 */
Route::get('authorize', [AuthorizeController::class, 'authorize'])->name('iam.oauth.authorize');
Route::post('token', [TokenController::class, 'token'])->name('iam.oauth.token');
