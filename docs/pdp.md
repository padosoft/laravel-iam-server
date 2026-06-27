---
title: Policy Decision Point
description: How the NativeSqlEngine evaluates RBAC + ABAC + ReBAC with deny-overrides, fail-closed, and a citable explanation.
---

# Policy Decision Point (PDP)

The PDP is the heart of the server: the single authority that decides allow/deny. It lives in
`src/Domain/Authorization/Pdp/`.

## The engine

`NativeSqlEngine` implements the `Contracts\Authorization\AuthorizationEngine` interface and exposes:

```php
public function decide(DecisionQuery $q): Decision;          // native, rich API
public function check(array $query): array;                  // contract entry point
public function listSubjects(string $relation, string $objectType, string $objectId): iterable;
public function listResources(SubjectRef $subject, string $relation): iterable;
```

It evaluates three models in one pass:

::: card "RBAC" icon:users
Role-based: the subject's roles (direct and inherited) grant permissions by slug.
:::

::: card "ABAC" icon:filter
Attribute-based: `ConditionEvaluator` checks declared conditions against the `context` you pass
(`amount <= 1000`, ownership, time windows…).
:::

::: card "ReBAC" icon:share-2
Relationship-based: `listSubjects` / `listResources` answer Zanzibar-style reverse-index queries (who can
read this document; what can this user edit).
:::

## The query and the decision

```php
new DecisionQuery(
    subject: new SubjectRef('user', '42'),
    permission: 'warehouse:stock.adjust',   // the full_key requested
    organizationId: 'org_123',
    applicationKey: 'warehouse',
    resourceRef: 'stock:SKU-9',
    context: ['amount' => 500],
    currentAal: 'aal1',
    explain: true,
);
```

returns a `Decision`:

```php
final readonly class Decision {
    public bool $allowed;
    public string $decisionId;       // cite this in your audit log
    public int $policyVersion;
    public bool $requiresStepUp;     // true ⇒ needs AAL2 before proceeding
    public ?string $requiredAal;
    public array $matched;           // [{type, key}] policies that fired
    public array $failedConditions;
    public array $explanation;       // human-readable, audit-citable
}
```

## Guarantees

::: callout warning "Deny-overrides, fail-closed"
If **any** applicable policy denies, the result is deny. If evaluation cannot complete — malformed query,
missing data, an exception — the result is **deny**, never allow. There is no path that turns an error into
an allow.
:::

## Step-up

A permission can require a higher assurance level. When `currentAal` is below what the policy needs, the
decision comes back `allowed = false`, `requiresStepUp = true`, `requiredAal = 'aal2'`. The caller triggers
a step-up (passkey/MFA) and retries with the elevated AAL.

## Over HTTP

The same engine is exposed on the Admin API:

- `POST /admin/decisions/check` — allow/deny.
- `POST /admin/decisions/explain` — decision with full explanation.
- `POST /admin/decisions/list-subjects` and `/list-resources` — ReBAC reverse-index.

In consuming apps, prefer [`laravel-iam-client`](https://github.com/padosoft/laravel-iam-client), which calls
these for you, caches decisions, and exposes an `iam.can` middleware and a Gate adapter.
