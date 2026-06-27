<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Padosoft\Iam\Http\HealthController;

/*
 * Rotte di health NON autenticate (M14). Liveness e readiness per orchestratore/load balancer.
 * Montate al prefix configurato (default /api/iam/v1) ma fuori dal gruppo autenticato.
 */
Route::get('health', [HealthController::class, 'live'])->name('iam.health.live');
Route::get('ready', [HealthController::class, 'ready'])->name('iam.health.ready');
