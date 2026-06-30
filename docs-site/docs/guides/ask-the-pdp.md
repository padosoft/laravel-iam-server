---
title: Ask the PDP
description: Build a DecisionQuery and call NativeSqlEngine — in-process or over HTTP. The Decision contract, the explanation, step-up, and why you usually call it through laravel-iam-client.
---

# Ask the PDP

The Policy Decision Point is the single authority on allow/deny. This guide shows how to ask it a question
and read the answer.

## The query

```php
use Padosoft\Iam\Domain\Authorization\Pdp\NativeSqlEngine;
use Padosoft\Iam\Domain\Authorization\Pdp\DecisionQuery;
use Padosoft\Iam\Contracts\Support\SubjectRef;

$decision = app(NativeSqlEngine::class)->decide(new DecisionQuery(
    subject: new SubjectRef('user', '42'),
    permission: 'warehouse:stock.adjust',   // the full_key requested
    organizationId: 'org_123',
    applicationKey: 'warehouse',
    resourceRef: 'stock:SKU-9',
    context: ['amount' => 500],
    currentAal: 'aal1',
    explain: true,
));
```

| Field | Meaning |
|---|---|
| `subject` | Who is acting — a `SubjectRef('type', 'id')`. |
| `permission` | The immutable slug being requested. |
| `organizationId` | The tenant the decision is scoped to. |
| `applicationKey` | The owning app (disambiguates the catalog). |
| `resourceRef` | Optional specific resource for ReBAC / ownership conditions. |
| `context` | Attributes the ABAC `ConditionEvaluator` reads (`amount`, ownership, time…). |
| `currentAal` | The assurance level reached at authentication — drives step-up. |
| `explain` | Populate the human-readable `explanation`. |

## The decision

```php
$decision->allowed;          // bool — deny-overrides, fail-closed
$decision->decisionId;       // cite this in your audit log
$decision->policyVersion;    // which catalog version decided
$decision->requiresStepUp;   // true ⇒ needs AAL2 before proceeding
$decision->requiredAal;      // e.g. 'aal2'
$decision->matched;          // [{type, key}] policies that fired
$decision->failedConditions; // ABAC conditions that did not hold
$decision->explanation;      // human-readable, audit-citable
```

The full shape is the [Decision contract](/reference/decision-contract).

## Reading the explanation

The explanation tells you *why*. Use it for debugging and for the message you record in audit — never to
re-derive the decision yourself:

```php
if (! $decision->allowed) {
    Log::info('denied', ['decision' => $decision->decisionId, 'why' => $decision->explanation]);
    abort(403, $decision->explanation[0] ?? 'denied');
}
```

## Step-up

A permission can require a higher [assurance level](/concepts/assurance-aal). When `currentAal` is below
what the policy needs, the decision returns `allowed = false`, `requiresStepUp = true`,
`requiredAal = 'aal2'`. The caller triggers a step-up (passkey / MFA) and retries with the elevated AAL:

```php
if ($decision->requiresStepUp) {
    return redirect()->route('stepup', ['return' => url()->current()]);
}
```

## Over HTTP

The same engine is on the Admin API. Responses are wrapped in a `data` envelope:

```bash
curl -X POST https://iam.example.com/api/iam/v1/decisions/check \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"subject":"user:42","permission":"warehouse:stock.adjust","context":{"amount":500}}'
# → { "data": { "allowed": true, "decision_id": "...", "requires_step_up": false } }
```

`POST /decisions/explain` returns the same decision with the full `explanation` array.

::: callout warning "Use the slash form" icon:slash
The real wire contract is `POST {base}/api/iam/v1/decisions/check` (and `/decisions/list-resources`). All
SDKs and the PHP client are aligned to this. Do not use any colon-style variant.
:::

## From a consuming app — prefer the client

```php
// in your app, with laravel-iam-client installed
Route::post('/stock/adjust', AdjustStock::class)->middleware('iam.can:warehouse:stock.adjust');
```

[`laravel-iam-client`](https://doc.laravel-iam-client.padosoft.com) calls `/decisions/check` for you, caches
decisions, verifies JWTs/JWKS, and exposes the `iam.can` middleware and a Gate adapter. Call
`NativeSqlEngine` directly only inside the server itself.

::: collapsible "ADR — one engine, two entrypoints (decide vs check)"
**Problem.** Internal callers want a rich typed API; the HTTP/SDK surface wants a stable array contract.

**Decision.** `NativeSqlEngine::decide(DecisionQuery): Decision` is the native API; `check(array): array`
is the `AuthorizationEngine` contract entrypoint used over the wire. Both run the same evaluation.

**Consequences.** No drift between in-process and remote decisions; the contract can evolve via the array
shape while the typed DTO serves internal code.
:::

## Next

- [ReBAC relationships](/guides/rebac-relationships) — per-resource, relationship-based access.
- [Authorization models](/concepts/authorization-models) — RBAC + ABAC + ReBAC, formally.
- [Decision contract](/reference/decision-contract) — every field of the response.
