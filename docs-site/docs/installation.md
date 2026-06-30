---
title: Installation
description: Requirements, composer install, publishing config, migrations, the routes and middleware the service provider registers, and choosing a login backend.
---

# Installation

## Requirements

| Requirement | Version |
|---|---|
| PHP | **8.3+** |
| Laravel | **13** |
| Database | MySQL, PostgreSQL or SQLite |
| OAuth engine | `league/oauth2-server` `^9.0` (pulled in automatically) |
| JWT | `lcobucci/jwt` `^5.0` (pulled in automatically) |

The package depends on [`padosoft/laravel-iam-contracts`](https://doc.laravel-iam-contracts.padosoft.com)
and `spatie/laravel-package-tools`. Heavy adapters (AWS KMS, LDAP, AI) are **`suggest`** dependencies, never
required.

## Install

```bash
composer require padosoft/laravel-iam-server
```

The package is auto-discovered through `extra.laravel.providers`
(`Padosoft\Iam\IamServiceProvider`) — no `config/app.php` edits.

## Publish configuration

```bash
php artisan vendor:publish --tag="laravel-iam-server-config"
```

This publishes two files:

- **`config/iam.php`** — identity, tokens, OAuth, the Admin API prefix, crypto, audit, observability and
  integration toggles.
- **`config/iam-governance.php`** — IGA feature gates, SoD toxic-combination rules and least-privilege
  thresholds.

See [Configuration](/operations/configuration) for every key.

## Run migrations

```bash
php artisan migrate
```

Migrations are loaded automatically (toggle with `iam.run_migrations`). They create the IAM tables:
identity & sessions, the authorization catalog, OAuth client/grant tables, signing & data keys,
applications & manifests, audit, governance, relations (ReBAC), groups, directory sources and approval
steps. The full list is in the [Database schema](/reference/database-schema).

## What the service provider registers

::: card "Routes" icon:route
- **Admin API** at `iam.admin.route_prefix` (default `api/iam/v1`) — `routes/admin.php`.
- **Health / readiness** at the same prefix, **unauthenticated** — `routes/health.php`.
- **OAuth2** at `iam.oauth.route_prefix` (default `oauth`) — `routes/oauth.php`.
- **OIDC** discovery & JWKS at root — `routes/oidc.php`.
:::

::: card "Middleware aliases" icon:shield
- `iam.admin_auth` → `AdminAuthenticate` (bearer-token admin auth).
- `iam.can` → `AuthorizeIamPermission` (delegates to the PDP, e.g. `iam.can:iam:manifests.apply`).
- `iam.idempotency` → `IdempotencyKey` (dedupe writes via `Idempotency-Key`).
:::

Registration of the Admin/OAuth routes can be turned off with `iam.admin.register_routes` and
`iam.oauth.register_routes` if you want to mount them yourself.

## Choose a login backend

The IdP issues tokens; *how* a user proves who they are is pluggable. The package `suggest`s — but does not
require — login backends:

::: tabs
== tab "Fortify"
```bash
composer require laravel/fortify
```
A native username/password backend.
== tab "Socialite"
```bash
composer require laravel/socialite
```
Federated / social login.
== tab "Passkeys"
```bash
composer require laravel/passkeys
```
WebAuthn / passkeys — satisfies AAL2 for [step-up](/concepts/assurance-aal).
:::

## Verify the install

```bash
php artisan route:list --path=api/iam/v1   # admin routes are mounted
curl http://localhost/api/iam/v1/health     # → ok (unauthenticated)
```

::: callout warning "Set an OAuth encryption key in production" icon:key-round
`iam.oauth.encryption_key` (`IAM_OAUTH_ENCRYPTION_KEY`, base64 32 bytes) encrypts authorization codes and
refresh tokens. Empty in dev derives it from `APP_KEY`; set an explicit key in production. See
[Key management](/operations/configuration#crypto--keys).
:::

## Next

- [Quickstart](/quickstart) — your first decision in five steps.
- [Core concepts](/core-concepts) — the mental model behind the server.
- [Configuration](/operations/configuration) — every config key explained.
