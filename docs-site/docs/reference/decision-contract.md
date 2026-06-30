---
title: Decision contract
description: The exact shape of DecisionQuery (input) and Decision (output), the HTTP data envelope for /decisions/*, and how to read allowed, requiresStepUp, matched, failedConditions and explanation.
---

# Decision contract

The contract between a caller and the PDP. This is the source of truth for what you send and what you get
back, in-process and over HTTP.

## Input — `DecisionQuery`

```php
new DecisionQuery(
    subject: new SubjectRef('user', '42'),  // who is acting (type:id)
    permission: 'warehouse:stock.adjust',   // the immutable slug requested
    organizationId: 'org_123',              // tenant scope
    applicationKey: 'warehouse',            // owning app (optional, disambiguates)
    resourceRef: 'stock:SKU-9',             // specific resource (optional; ReBAC/ownership)
    context: ['amount' => 500],             // attributes for ABAC conditions
    currentAal: 'aal1',                     // assurance level reached at auth
    explain: true,                          // populate the explanation
);
```

| Field | Type | Required | Meaning |
|---|---|:---:|---|
| `subject` | `SubjectRef` | yes | The acting subject (`type:id`). |
| `permission` | `string` | yes | Immutable slug `app_key:permission`. |
| `organizationId` | `string` | yes | Tenant the decision is scoped to. |
| `applicationKey` | `string` | no | Owning application key. |
| `resourceRef` | `string` | no | Specific resource for ReBAC / ownership. |
| `context` | `array` | no | Attributes read by `ConditionEvaluator`. |
| `currentAal` | `string` | no | `aal1` · `aal2` · `aal3`. |
| `explain` | `bool` | no | Populate `explanation`. |

## Output — `Decision`

```php
final readonly class Decision {
    public bool $allowed;          // deny-overrides, fail-closed
    public string $decisionId;     // cite this in your audit log
    public int $policyVersion;     // which applied-manifest version decided
    public bool $requiresStepUp;   // true ⇒ needs a higher AAL first
    public ?string $requiredAal;   // e.g. 'aal2'
    public array $matched;         // [{type, key}] policies that fired
    public array $failedConditions;// ABAC conditions that did not hold
    public array $explanation;     // human-readable, audit-citable
}
```

| Field | Meaning |
|---|---|
| `allowed` | The verdict. Always treat absence/error as `false`. |
| `decisionId` | Stable id to record in audit and correlate later. |
| `policyVersion` | The catalog version that decided — attributes a decision to a policy. |
| `requiresStepUp` | `true` when the grant exists but the AAL is insufficient. |
| `requiredAal` | The minimum AAL the policy needs. |
| `matched` | The policies that contributed (`{type, key}`). |
| `failedConditions` | ABAC conditions that evaluated false. |
| `explanation` | Why — for logging/debugging, not for re-deriving the verdict. |

## HTTP shape

`POST /api/iam/v1/decisions/check` (and `/decisions/explain`) return the decision under a `data` envelope:

```json
{
  "data": {
    "allowed": true,
    "decision_id": "dec_01J...",
    "policy_version": 7,
    "requires_step_up": false,
    "matched": [ { "type": "role", "key": "warehouse:operator" } ],
    "failed_conditions": [],
    "explanation": [ "granted by role warehouse:operator", "condition amount<=1000 satisfied" ]
  }
}
```

::: callout warning "The wire form is the slash path" icon:slash
The real endpoints are `POST {base}/api/iam/v1/decisions/check` and `/decisions/list-resources`. All SDKs
and the PHP client align to this slash form and the `data` envelope — do not use any colon-style variant.
:::

## Reading the verdict safely

```php
$allowed = $decision->allowed ?? false;     // default deny
if ($decision->requiresStepUp) { /* step up to requiredAal, retry */ }
// log $decision->explanation; never re-derive allow/deny from it
```

## Next

- [Ask the PDP](/guides/ask-the-pdp) — using this contract in practice.
- [PDP decision pipeline](/architecture/pdp-pipeline) — how the fields are computed.
- [Assurance levels](/concepts/assurance-aal) — `requiresStepUp` / `requiredAal`.
