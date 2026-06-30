---
title: Quickstart
description: From composer require to your first allow/deny decision in five steps — install, migrate, register an application manifest, and call the PDP both in-process and over HTTP.
---

# Quickstart

This page takes you from nothing to a verifiable authorization decision. It assumes a Laravel 13 app and a
database. For the longer version see [Installation](/installation) and [Core concepts](/core-concepts).

## 1. Install & migrate

::: steps
1. **Require the package**
   ```bash
   composer require padosoft/laravel-iam-server
   ```
2. **Publish config**
   ```bash
   php artisan vendor:publish --tag="laravel-iam-server-config"
   ```
   This publishes `config/iam.php` and `config/iam-governance.php`.
3. **Migrate**
   ```bash
   php artisan migrate
   ```
   The service provider loads the package migrations and registers the Admin API (`/api/iam/v1`), the OAuth
   (`/oauth`) and OIDC routes, plus the `iam.admin_auth` / `iam.can` / `iam.idempotency` middleware
   automatically.
:::

## 2. Declare an application manifest

The core hardcodes **no** permissions. Each consuming app declares what it needs in a *manifest*. Slugs are
immutable and namespaced `app_key:permission`:

```jsonc
{
  "app_key": "warehouse",
  "permissions": [
    { "key": "warehouse:stock.read",   "label": "Read stock" },
    { "key": "warehouse:stock.adjust", "label": "Adjust stock",
      "condition": { "attr": "amount", "op": "<=", "value": 1000 } }
  ],
  "roles": [
    { "key": "warehouse:operator", "permissions": ["warehouse:stock.read", "warehouse:stock.adjust"] }
  ]
}
```

## 3. Submit, approve, apply

A manifest is **validated and diffed** before anything changes, then approved and applied:

```bash
# submit
curl -X POST https://iam.example.com/api/iam/v1/applications/warehouse/manifests \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d @warehouse-manifest.json

# inspect the diff, then approve + apply
curl https://iam.example.com/api/iam/v1/manifests/{id}/diff    -H "Authorization: Bearer $ADMIN_TOKEN"
curl -X POST https://iam.example.com/api/iam/v1/manifests/{id}/approve -H "Authorization: Bearer $ADMIN_TOKEN"
curl -X POST https://iam.example.com/api/iam/v1/manifests/{id}/apply   -H "Authorization: Bearer $ADMIN_TOKEN"
```

You can do the same from the CLI: `php artisan iam:manifest:validate path.json` and
`php artisan iam:manifest:apply path.json --approve`. See the [CLI reference](/operations/cli).

## 4. Ask the PDP (in-process)

The decision point is the only authority on allow/deny. Build a `DecisionQuery` and call the engine:

```php
use Padosoft\Iam\Domain\Authorization\Pdp\NativeSqlEngine;
use Padosoft\Iam\Domain\Authorization\Pdp\DecisionQuery;
use Padosoft\Iam\Contracts\Support\SubjectRef;

$decision = app(NativeSqlEngine::class)->decide(new DecisionQuery(
    subject: new SubjectRef('user', '42'),
    permission: 'warehouse:stock.adjust',
    organizationId: 'org_123',
    context: ['amount' => 500],   // evaluated by the ABAC condition above
    explain: true,
));

$decision->allowed;        // bool — deny-overrides, fail-closed
$decision->decisionId;     // cite this in your audit log
$decision->explanation;    // why it decided this way
$decision->requiresStepUp; // true ⇒ ask the user for AAL2 first
```

With `amount = 500` the condition `amount <= 1000` holds, so a user holding `warehouse:operator` is
**allowed**. With `amount = 5000` the same user is **denied** — the condition fails.

## 5. Or over HTTP

The same engine is exposed on the Admin API. The server wraps responses in a `data` envelope:

```bash
curl -X POST https://iam.example.com/api/iam/v1/decisions/check \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"subject":"user:42","permission":"warehouse:stock.adjust","context":{"amount":500}}'
# → { "data": { "allowed": true, "decision_id": "...", "explanation": [ ... ] } }
```

::: callout tip "Don't call the PDP directly from consuming apps" icon:lightbulb
In your **consuming** apps you normally install
[`laravel-iam-client`](https://doc.laravel-iam-client.padosoft.com) and protect routes with its `iam.can`
middleware / Gate adapter, which calls `/decisions/check` for you, caches decisions, and verifies JWTs.
:::

## Verify it's working

```bash
# liveness / readiness (unauthenticated, same prefix)
curl https://iam.example.com/api/iam/v1/health
curl https://iam.example.com/api/iam/v1/ready

# the audit chain is intact
curl -X POST https://iam.example.com/api/iam/v1/audit/verify-chain -H "Authorization: Bearer $ADMIN_TOKEN"
```

## Where to go next

::: grids
  ::: grid
    ::: card "Core concepts" icon:workflow
    Subjects, manifests, the PDP, fail-closed — the mental model. **[Read →](/core-concepts)**
    :::
  :::
  ::: grid
    ::: card "Register an application" icon:boxes
    The full manifest lifecycle: validate, diff, approve, apply, rollback. **[Open →](/guides/register-application)**
    :::
  :::
  ::: grid
    ::: card "Ask the PDP" icon:scale
    RBAC + ABAC + ReBAC, step-up, and the decision contract. **[Open →](/guides/ask-the-pdp)**
    :::
  :::
:::
