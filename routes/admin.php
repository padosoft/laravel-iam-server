<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Padosoft\Iam\Http\Admin\Controllers\UsersController;

/*
 * Admin API (doc 16). Base path /api/iam/v1 (configurabile). Tutte le rotte sono autenticate
 * (AdminAuthenticate) e le mutazioni passano da Idempotency-Key; ogni rotta dichiara il permesso
 * richiesto col middleware `iam.can:<permission>` (PDP = autorità, fail-closed).
 */

// Users (doc 16 §3.2)
Route::get('users', [UsersController::class, 'index'])->middleware('iam.can:iam:users.read');
Route::get('users/{user}', [UsersController::class, 'show'])->middleware('iam.can:iam:users.read');
Route::get('users/{user}/effective-permissions', [UsersController::class, 'effectivePermissions'])->middleware('iam.can:iam:users.read');
Route::post('users/{user}/suspend', [UsersController::class, 'suspend'])->middleware('iam.can:iam:users.manage');
Route::post('users/{user}/reactivate', [UsersController::class, 'reactivate'])->middleware('iam.can:iam:users.manage');
