<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Padosoft\Iam\Http\Admin\Controllers\AccessRequestsController;
use Padosoft\Iam\Http\Admin\Controllers\AccessReviewsController;
use Padosoft\Iam\Http\Admin\Controllers\ApplicationsController;
use Padosoft\Iam\Http\Admin\Controllers\AuditController;
use Padosoft\Iam\Http\Admin\Controllers\DecisionsController;
use Padosoft\Iam\Http\Admin\Controllers\DirectorySourcesController;
use Padosoft\Iam\Http\Admin\Controllers\FederatedProvidersController;
use Padosoft\Iam\Http\Admin\Controllers\GroupsController;
use Padosoft\Iam\Http\Admin\Controllers\ManifestsController;
use Padosoft\Iam\Http\Admin\Controllers\MetricsController;
use Padosoft\Iam\Http\Admin\Controllers\PoliciesWizardController;
use Padosoft\Iam\Http\Admin\Controllers\RecommendationsController;
use Padosoft\Iam\Http\Admin\Controllers\RelationsController;
use Padosoft\Iam\Http\Admin\Controllers\SessionsController;
use Padosoft\Iam\Http\Admin\Controllers\UsersController;
use Padosoft\Iam\Http\Admin\Controllers\WebhooksController;

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
Route::post('users/{user}/sessions/revoke-all', [SessionsController::class, 'revokeAllForUser'])->middleware('iam.can:iam:sessions.manage');

// Decisions / Policy Playground (doc 16 §3.15)
Route::post('decisions/check', [DecisionsController::class, 'check'])->middleware('iam.can:iam:decisions.check');
Route::post('decisions/explain', [DecisionsController::class, 'explain'])->middleware('iam.can:iam:decisions.explain');
Route::post('decisions/list-subjects', [DecisionsController::class, 'listSubjects'])->middleware('iam.can:iam:decisions.explain');
Route::post('decisions/list-resources', [DecisionsController::class, 'listResources'])->middleware('iam.can:iam:decisions.explain');

// Relations (tuple ReBAC, doc 18 §8)
Route::post('relations', [RelationsController::class, 'store'])->middleware('iam.can:iam:relations.manage');
Route::delete('relations', [RelationsController::class, 'destroy'])->middleware('iam.can:iam:relations.manage');

// Sessions (doc 16 §3.16)
Route::get('sessions', [SessionsController::class, 'index'])->middleware('iam.can:iam:sessions.read');
Route::get('sessions/{session}', [SessionsController::class, 'show'])->middleware('iam.can:iam:sessions.read');
Route::post('sessions/{session}/revoke', [SessionsController::class, 'revoke'])->middleware('iam.can:iam:sessions.manage');

// Access Reviews / Certification (doc 16 §3, doc 14 §3)
Route::get('access-reviews/campaigns', [AccessReviewsController::class, 'index'])->middleware('iam.can:iam:access_review.manage');
Route::post('access-reviews/campaigns', [AccessReviewsController::class, 'store'])->middleware('iam.can:iam:access_review.manage');
Route::post('access-reviews/campaigns/{campaign}/open', [AccessReviewsController::class, 'open'])->middleware('iam.can:iam:access_review.manage');
Route::post('access-reviews/campaigns/{campaign}/close', [AccessReviewsController::class, 'close'])->middleware('iam.can:iam:access_review.manage');
Route::get('access-reviews/campaigns/{campaign}/items', [AccessReviewsController::class, 'items'])->middleware('iam.can:iam:access_review.manage');
Route::post('access-reviews/items/{item}/certify', [AccessReviewsController::class, 'certify'])->middleware('iam.can:iam:access_review.manage');
Route::post('access-reviews/items/{item}/revoke', [AccessReviewsController::class, 'revoke'])->middleware('iam.can:iam:access_review.manage');

// Access Requests self-service (doc 16 §3, doc 14 §4)
Route::get('access-requests', [AccessRequestsController::class, 'index'])->middleware('iam.can:iam:access_request.review');
Route::get('access-requests/catalog', [AccessRequestsController::class, 'catalog'])->middleware('iam.can:iam:access_request.use');
Route::post('access-requests', [AccessRequestsController::class, 'store'])->middleware('iam.can:iam:access_request.use');
Route::post('access-requests/{accessRequest}/approve', [AccessRequestsController::class, 'approve'])->middleware('iam.can:iam:access_request.review');
Route::post('access-requests/{accessRequest}/reject', [AccessRequestsController::class, 'reject'])->middleware('iam.can:iam:access_request.review');
// Approver chain multi-step (doc 19 §9): grant solo all'ultimo step; reject fail-closed
Route::get('access-requests/{accessRequest}/steps', [AccessRequestsController::class, 'steps'])->middleware('iam.can:iam:access_request.review');
Route::post('access-requests/{accessRequest}/steps/{step}/approve', [AccessRequestsController::class, 'approveStep'])->middleware('iam.can:iam:access_request.review');
Route::post('access-requests/{accessRequest}/steps/{step}/reject', [AccessRequestsController::class, 'rejectStep'])->middleware('iam.can:iam:access_request.review');

// Groups (doc 16 §3.4, doc 19 §3) — soggetti first-class; membership scrive anche la tupla ReBAC (M16)
Route::get('groups', [GroupsController::class, 'index'])->middleware('iam.can:iam:groups.read');
Route::post('groups', [GroupsController::class, 'store'])->middleware('iam.can:iam:groups.manage');
Route::get('groups/{group}', [GroupsController::class, 'show'])->middleware('iam.can:iam:groups.read');
Route::patch('groups/{group}', [GroupsController::class, 'update'])->middleware('iam.can:iam:groups.manage');
Route::delete('groups/{group}', [GroupsController::class, 'destroy'])->middleware('iam.can:iam:groups.manage');
Route::get('groups/{group}/members', [GroupsController::class, 'members'])->middleware('iam.can:iam:groups.read');
Route::post('groups/{group}/members', [GroupsController::class, 'addMember'])->middleware('iam.can:iam:groups.manage');
Route::delete('groups/{group}/members', [GroupsController::class, 'removeMember'])->middleware('iam.can:iam:groups.manage');

// Federated Providers (doc 16 §3.8, doc 19 §4) — secret write-only (cifrato), mai restituito
Route::get('federated-providers', [FederatedProvidersController::class, 'index'])->middleware('iam.can:iam:federated.read');
Route::post('federated-providers', [FederatedProvidersController::class, 'store'])->middleware('iam.can:iam:federated.manage');
Route::get('federated-providers/{provider}', [FederatedProvidersController::class, 'show'])->middleware('iam.can:iam:federated.read');
Route::patch('federated-providers/{provider}', [FederatedProvidersController::class, 'update'])->middleware('iam.can:iam:federated.manage');
Route::delete('federated-providers/{provider}', [FederatedProvidersController::class, 'destroy'])->middleware('iam.can:iam:federated.manage');
Route::post('federated-providers/{provider}/test', [FederatedProvidersController::class, 'test'])->middleware('iam.can:iam:federated.manage');

// Directory Sources (doc 16 §3.9, doc 19 §5) — sync/test delegati al modulo -directory (409 se assente)
Route::get('directory-sources', [DirectorySourcesController::class, 'index'])->middleware('iam.can:iam:directory.read');
Route::post('directory-sources', [DirectorySourcesController::class, 'store'])->middleware('iam.can:iam:directory.manage');
Route::get('directory-sources/{source}', [DirectorySourcesController::class, 'show'])->middleware('iam.can:iam:directory.read');
Route::patch('directory-sources/{source}', [DirectorySourcesController::class, 'update'])->middleware('iam.can:iam:directory.manage');
Route::delete('directory-sources/{source}', [DirectorySourcesController::class, 'destroy'])->middleware('iam.can:iam:directory.manage');
Route::post('directory-sources/{source}/sync', [DirectorySourcesController::class, 'sync'])->middleware('iam.can:iam:directory.manage');
Route::post('directory-sources/{source}/test', [DirectorySourcesController::class, 'test'])->middleware('iam.can:iam:directory.manage');

// Policy Wizard (doc 16 §3.14, doc 19 §6) — solo controller: preview non scrive, commit idempotente
Route::get('policies-wizard/permissions', [PoliciesWizardController::class, 'permissions'])->middleware('iam.can:iam:policies.read');
Route::post('policies-wizard/preview', [PoliciesWizardController::class, 'preview'])->middleware('iam.can:iam:policies.read');
Route::post('policies-wizard/commit', [PoliciesWizardController::class, 'commit'])->middleware('iam.can:iam:grants.manage');

// Webhooks (doc 16 §3.24, doc 19 §7) — CRUD + test-delivery + DLQ replay sul backend M7
Route::get('webhooks', [WebhooksController::class, 'index'])->middleware('iam.can:iam:webhooks.read');
Route::post('webhooks', [WebhooksController::class, 'store'])->middleware('iam.can:iam:webhooks.manage');
Route::post('webhooks/deliveries/{delivery}/replay', [WebhooksController::class, 'replay'])->middleware('iam.can:iam:webhooks.manage');
Route::get('webhooks/{subscription}', [WebhooksController::class, 'show'])->middleware('iam.can:iam:webhooks.read');
Route::patch('webhooks/{subscription}', [WebhooksController::class, 'update'])->middleware('iam.can:iam:webhooks.manage');
Route::delete('webhooks/{subscription}', [WebhooksController::class, 'destroy'])->middleware('iam.can:iam:webhooks.manage');
Route::post('webhooks/{subscription}/test', [WebhooksController::class, 'test'])->middleware('iam.can:iam:webhooks.manage');
Route::get('webhooks/{subscription}/deliveries', [WebhooksController::class, 'deliveries'])->middleware('iam.can:iam:webhooks.read');

// Metrics (doc 16 §3.1, doc 19 §8) — read-only, aggregazioni bounded, tenant-scoped
Route::get('metrics/decisions', [MetricsController::class, 'decisions'])->middleware('iam.can:iam:metrics.read');
Route::get('metrics/grants', [MetricsController::class, 'grants'])->middleware('iam.can:iam:metrics.read');
Route::get('metrics/audit', [MetricsController::class, 'auditMetrics'])->middleware('iam.can:iam:metrics.read');

// Least-privilege / anomaly recommendations (doc 16 §3, doc 14 §7)
Route::get('recommendations/least-privilege', [RecommendationsController::class, 'leastPrivilege'])->middleware('iam.can:iam:least_privilege.view');

// Applications + Manifests (doc 16 §3.5/§3.10, il moat)
Route::get('applications', [ApplicationsController::class, 'index'])->middleware('iam.can:iam:applications.read');
Route::get('applications/{app}', [ApplicationsController::class, 'show'])->middleware('iam.can:iam:applications.read');
Route::get('applications/{app}/manifest', [ApplicationsController::class, 'manifest'])->middleware('iam.can:iam:applications.read');
Route::post('applications/{app}/manifests', [ManifestsController::class, 'store'])->middleware('iam.can:iam:manifests.submit');
Route::get('manifests', [ManifestsController::class, 'index'])->middleware('iam.can:iam:manifests.read');
Route::get('manifests/{manifest}', [ManifestsController::class, 'show'])->middleware('iam.can:iam:manifests.read');
Route::get('manifests/{manifest}/diff', [ManifestsController::class, 'diff'])->middleware('iam.can:iam:manifests.read');
Route::post('manifests/{manifest}/approve', [ManifestsController::class, 'approve'])->middleware('iam.can:iam:manifests.approve');
Route::post('manifests/{manifest}/reject', [ManifestsController::class, 'reject'])->middleware('iam.can:iam:manifests.approve');
Route::post('manifests/{manifest}/apply', [ManifestsController::class, 'apply'])->middleware('iam.can:iam:manifests.apply');
Route::post('manifests/{manifest}/rollback', [ManifestsController::class, 'rollback'])->middleware('iam.can:iam:manifests.apply');

// Audit (doc 16 §3, doc 12) — sola lettura
Route::get('audit/events', [AuditController::class, 'eventsIndex'])->middleware('iam.can:iam:audit.read');
Route::post('audit/verify-chain', [AuditController::class, 'verifyChain'])->middleware('iam.can:iam:audit.read');
