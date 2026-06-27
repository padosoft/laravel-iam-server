---
title: Reference
description: Key classes, routes and config of laravel-iam-server, grouped by subsystem.
---

# Reference

Everything lives under namespace `Padosoft\Iam\` (`src/`). Selected, real entry points by subsystem.

## Authorization (PDP) — `Domain/Authorization/Pdp/`

| Class | Purpose |
| --- | --- |
| `NativeSqlEngine` | The PDP. `decide(DecisionQuery): Decision`, `check()`, `listSubjects()`, `listResources()`. RBAC+ABAC+ReBAC, deny-overrides, fail-closed. |
| `DecisionQuery` | Input: subject, permission, organizationId, applicationKey, resourceRef, context, currentAal, explain. |
| `Decision` | Output: allowed, decisionId, policyVersion, requiresStepUp, requiredAal, matched, failedConditions, explanation. |
| `ConditionEvaluator` | ABAC condition evaluation against `context`. |

## Applications & manifests — `Domain/Applications/`

| Class | Purpose |
| --- | --- |
| `Manifest/ManifestValidator` | Validate a submitted manifest. |
| `Manifest/ManifestDiffer` | Diff a new manifest against the applied one. |
| `Manifest/ManifestApplier` | Apply an approved manifest (and rollback). |
| `Manifest/ManifestRegistry` | Registry of applications and their applied manifests. |

## Crypto — `Domain/Crypto/`

| Class | Purpose |
| --- | --- |
| `LocalKeyProvider` | Envelope encryption key provider (`KeyProvider` contract). |
| `LocalSecretCipher` | Encrypt/decrypt/`shred` secrets with a `scope` (crypto-shredding). |

## OAuth & OIDC — `Domain/OAuth/`

`AuthorizationServerFactory`, `Grants/`, `Entities/`, `Repositories/`, `ResponseTypes/`, `Token/`,
`ClientAuthenticator`, `RefreshTokenCrypto`, `Oidc/` (MIT base).

## Audit — `Domain/Audit/`

`AuditHasher`, `AuditChainAppender`, `AuditChainVerifier`, `AuditCheckpointer`, `AuditVerificationResult`,
`Export/`, `Webhooks/`, `Outbox/`, `Pii/`, `Events/`.

## Governance — `Domain/Governance/`

`Reviews/CampaignEngine`, `Reviews/ReviewSignals`, `Requests/`, `Recommendations/`, `GrantUsageRecorder`,
`NativeFeatureScope`.

## HTTP & observability — `Http/`, `Observability/`

`Http/Admin/` (controllers + `Middleware/` `iam.admin_auth`/`iam.can`/`iam.idempotency`),
`Http/HealthController`, `Observability/HealthCheck`, `Tracer` / `NullTracer` / `LogTracer`.

## Routes & config

| File | Contents |
| --- | --- |
| `routes/admin.php` | Admin API. |
| `routes/oauth.php` | OAuth2 endpoints. |
| `routes/oidc.php` | OIDC endpoints. |
| `routes/health.php` | Health / readiness. |
| `resources/openapi.yaml` | The admin HTTP contract (enforced by `OpenApiSpecTest`). |
| `config/iam.php`, `config/iam-governance.php` | Configuration (publish tag `laravel-iam-server-config`). |
