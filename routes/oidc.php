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

// Published JSON Schema of the application manifest (laravel-iam.manifest.v2), so any app/CI in any language
// can validate a manifest locally before pushing it to the Admin API.
Route::get('.well-known/iam-manifest-schema.json', fn () => response(
    (string) file_get_contents(__DIR__.'/../resources/manifest.schema.json'),
    200,
    ['Content-Type' => 'application/schema+json']
))->name('iam.manifest.schema');
