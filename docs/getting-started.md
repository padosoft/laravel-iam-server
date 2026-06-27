---
title: Getting started
description: Install laravel-iam-server, run migrations, register an application and ask the PDP your first decision.
---

# Getting started

## Requirements

- PHP **8.3+**
- Laravel **13**
- A database (MySQL, PostgreSQL or SQLite)

## Install

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
   The service provider loads the package migrations and registers the Admin API, OAuth and OIDC routes plus
   the `iam.can` / `iam.admin_auth` / `iam.idempotency` middleware automatically.
:::

## Register your first application

Applications **declare** what they need in a *manifest* — the core never hardcodes permissions. Submit it
through the Admin API, then approve and apply it:

```bash
# 1. submit
curl -X POST https://iam.example.com/admin/applications/warehouse/manifests \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d @warehouse-manifest.json

# 2. approve + apply (validated and diffed first)
curl -X POST https://iam.example.com/admin/manifests/{id}/approve -H "Authorization: Bearer $ADMIN_TOKEN"
curl -X POST https://iam.example.com/admin/manifests/{id}/apply   -H "Authorization: Bearer $ADMIN_TOKEN"
```

## Ask your first decision

```php
use Padosoft\Iam\Domain\Authorization\Pdp\NativeSqlEngine;
use Padosoft\Iam\Domain\Authorization\Pdp\DecisionQuery;
use Padosoft\Iam\Contracts\Support\SubjectRef;

$decision = app(NativeSqlEngine::class)->decide(new DecisionQuery(
    subject: new SubjectRef('user', '42'),
    permission: 'warehouse:stock.adjust',
    organizationId: 'org_123',
    context: ['amount' => 500],
    explain: true,
));

if (! $decision->allowed) {
    abort(403, $decision->explanation[0] ?? 'denied');
}
```

::: callout warning "Fail-closed"
Any error — bad input, missing policy, transport failure — resolves to **deny**, never to allow and never to
an opaque 500. Design your callers to treat a thrown/denied decision as "no".
:::

## Next

- [Concepts](concepts.md) — understand subjects, manifests and the decision flow.
- [Policy Decision Point](pdp.md) — RBAC + ABAC + ReBAC in depth.
- In consuming apps, install [`laravel-iam-client`](https://github.com/padosoft/laravel-iam-client) instead
  of calling the PDP directly.
