---
title: PHP API
description: Key classes and entry points under the Padosoft\Iam namespace, grouped by subsystem — the PDP, manifests, crypto, OAuth/OIDC, audit, governance, HTTP and observability.
---

# PHP API reference

Everything lives under the `Padosoft\Iam\` namespace (`src/`). These are the real, load-bearing entry points
by subsystem. The server implements the
[`laravel-iam-contracts`](https://doc.laravel-iam-contracts.padosoft.com) interfaces.

## Authorization (PDP) — `Domain/Authorization/Pdp/`

| Class | Purpose |
|---|---|
| `NativeSqlEngine` | The PDP. `decide(DecisionQuery): Decision`, `check(array): array`, `listSubjects()`, `listResources()`. RBAC+ABAC+ReBAC, deny-overrides, fail-closed. Implements `Contracts\AuthorizationEngine`. |
| `DecisionQuery` | Input: `subject`, `permission`, `organizationId`, `applicationKey`, `resourceRef`, `context`, `currentAal`, `explain`. |
| `Decision` | Output: `allowed`, `decisionId`, `policyVersion`, `requiresStepUp`, `requiredAal`, `matched`, `failedConditions`, `explanation`. |
| `ConditionEvaluator` | ABAC condition evaluation against `context`. |

```php
public function decide(DecisionQuery $q): Decision;
public function check(array $query): array;
public function listSubjects(string $relation, string $objectType, string $objectId): iterable;
public function listResources(SubjectRef $subject, string $relation): iterable;
```

## Applications & manifests — `Domain/Applications/`

| Class | Purpose |
|---|---|
| `Manifest/ManifestValidator` | Validate a submitted manifest. |
| `Manifest/ManifestDiffer` | Diff a new manifest against the applied one. |
| `Manifest/ManifestApplier` | Apply an approved manifest (and rollback). |
| `Manifest/ManifestRegistry` | Registry of applications and their applied manifests. |

## Crypto — `Domain/Crypto/`

| Class | Purpose |
|---|---|
| `LocalKeyProvider` | Envelope-encryption key provider (`KeyProvider` contract). |
| `LocalSecretCipher` | Encrypt / decrypt / `shred` secrets with a `scope` (crypto-shredding). |

## OAuth & OIDC — `Domain/OAuth/`

`AuthorizationServerFactory`, `Grants/`, `Entities/`, `Repositories/`, `ResponseTypes/`, `Token/`,
`ClientAuthenticator`, `RefreshTokenCrypto`, `Oidc/` (MIT base).

## Audit — `Domain/Audit/`

`AuditHasher`, `AuditChainAppender`, `AuditChainVerifier`, `AuditCheckpointer`, `AuditVerificationResult`,
`Export/`, `Webhooks/`, `Outbox/`, `Pii/`, `Events/`.

## Governance — `Domain/Governance/`

`Reviews/CampaignEngine`, `Reviews/ReviewSignals`, `Requests/`, `Recommendations/`, `GrantUsageRecorder`,
`NativeFeatureScope`.

## Identity — `Domain/Identity/`

`Session/` (server-side, revocable session registry), `Assurance/` (AAL / step-up),
`Federation/` (`iam_federated_identities`), `Models/`.

## HTTP & observability — `Http/`, `Observability/`

`Http/Admin/` (controllers + `Middleware/`: `AdminAuthenticate` / `AuthorizeIamPermission` /
`IdempotencyKey`), `Http/HealthController`, `Observability/HealthCheck`, `Tracer` / `NullTracer` /
`LogTracer`.

## Shared value objects (from contracts)

| Type | Shape |
|---|---|
| `SubjectRef` | `('type', 'id')` — `user:42`, `service_account:7` |
| `ResourceRef` | `('type', 'id')` — `doc:42` |

## Worked example

```php
use Padosoft\Iam\Domain\Authorization\Pdp\NativeSqlEngine;
use Padosoft\Iam\Domain\Authorization\Pdp\DecisionQuery;
use Padosoft\Iam\Contracts\Support\SubjectRef;

$engine = app(NativeSqlEngine::class);

$decision = $engine->decide(new DecisionQuery(
    subject: new SubjectRef('user', '42'),
    permission: 'warehouse:stock.adjust',
    organizationId: 'org_123',
    context: ['amount' => 500],
    explain: true,
));

if ($decision->requiresStepUp) { /* AAL2, retry */ }
$allowed = $decision->allowed;            // deny-overrides, fail-closed
```

::: callout warning "Resolve via the container, prefer the client in apps" icon:package
Resolve these through Laravel's container (`app(...)`) so bound contract implementations are used. In
**consuming** apps, call the PDP through
[`laravel-iam-client`](https://doc.laravel-iam-client.padosoft.com), not `NativeSqlEngine` directly.
:::

## Next

- [Decision contract](/reference/decision-contract) — every field of `Decision`.
- [PDP decision pipeline](/architecture/pdp-pipeline) — how `decide` runs.
- [Admin API](/reference/admin-api) — the HTTP surface.
