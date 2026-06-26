<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Padosoft\Iam\Http\Controllers\OAuth\DiscoveryController;
use Padosoft\Iam\Http\Controllers\OAuth\JwksController;
use Padosoft\Iam\Http\Controllers\OAuth\UserinfoController;

/*
 * Endpoint OIDC/metadata a livello root (NON sotto il prefix /oauth), doc 13 §7.
 */
Route::get('.well-known/jwks.json', [JwksController::class, 'jwks'])->name('iam.oidc.jwks');
Route::get('.well-known/openid-configuration', [DiscoveryController::class, 'openidConfiguration'])->name('iam.oidc.discovery');
Route::get('.well-known/oauth-authorization-server', [DiscoveryController::class, 'oauthAuthorizationServer'])->name('iam.oauth.metadata');
Route::get('oidc/userinfo', [UserinfoController::class, 'userinfo'])->name('iam.oidc.userinfo');
