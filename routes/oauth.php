<?php

declare(strict_types=1);

use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Facades\Route;
use Padosoft\Iam\Http\Controllers\OAuth\AuthorizeController;
use Padosoft\Iam\Http\Controllers\OAuth\IntrospectionController;
use Padosoft\Iam\Http\Controllers\OAuth\RevocationController;
use Padosoft\Iam\Http\Controllers\OAuth\TokenController;

/*
 * Endpoint OAuth2 / OIDC (doc 13 §7). Il prefix è configurabile (iam.oauth.route_prefix).
 */
// /authorize è browser-facing: StartSession per leggere il sid della sessione IAM (M5.4).
Route::get('authorize', [AuthorizeController::class, 'authorize'])
    ->middleware(StartSession::class)
    ->name('iam.oauth.authorize');
Route::post('token', [TokenController::class, 'token'])->name('iam.oauth.token');
Route::post('introspect', [IntrospectionController::class, 'introspect'])->name('iam.oauth.introspect');
Route::post('revoke', [RevocationController::class, 'revoke'])->name('iam.oauth.revoke');
