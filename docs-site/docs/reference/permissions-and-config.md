---
title: Permissions & config
description: The governance permission slugs, feature gate defaults, least-privilege thresholds and SoD rules — plus the key config files, publish tag, routes and middleware aliases in one place.
---

# Permissions & config reference

A quick lookup for the governance permission slugs, the feature-gate defaults and the operational knobs.
Full prose is in [Configuration](/operations/configuration).

## Governance permission slugs

Governance features are gated per layer / app / role / user via `NativeFeatureScope`. Each feature has a
default state and (where applicable) a controlling permission:

| Feature | Default | Permission slug |
|---|---|---|
| Access review | `on` | `iam:access_review.manage` |
| Access request | `off` | `iam:access_request.use` |
| PIM (JIT elevation) | `off` | `iam:pim.activate` |
| Separation of Duties | `detect` | — |
| Least-privilege | `on` | `iam:least_privilege.view` |
| Anomaly detection | `on` | `iam:anomaly.view` |

`off` features are privacy-by-default (e.g. the access-request catalog is empty until enabled). `detect`
means observe-and-flag without blocking.

## Least-privilege thresholds

`config/iam-governance.php` → `least_privilege`:

| Key | Default | Meaning |
|---|---|---|
| `unused_days` | 90 | grant unused N days → revoke candidate |
| `dormant_days` | 90 | account no login N days → dormant |
| `wide_role_permissions` | 50 | role with > N permissions → too broad |

## SoD toxic combinations

`config/iam-governance.php` → `toxic_combinations` — permission pairs that must not be co-held:

```php
'toxic_combinations' => [
    // ['finance:vendor.create', 'finance:payment.approve'],
],
```

## Config files & publish tag

| File | Holds |
|---|---|
| `config/iam.php` | identity, tokens, oauth, admin, directory, crypto, audit, observability, governance, ai, mcp, integrations |
| `config/iam-governance.php` | feature gates, toxic combinations, least-privilege thresholds |

```bash
php artisan vendor:publish --tag="laravel-iam-server-config"
```

## Routes & middleware

| File | Prefix (config key) | Auth |
|---|---|---|
| `routes/admin.php` | `api/iam/v1` (`iam.admin.route_prefix`) | `iam.admin_auth` + `iam.can` |
| `routes/health.php` | same prefix | unauthenticated |
| `routes/oauth.php` | `oauth` (`iam.oauth.route_prefix`) | OAuth |
| `routes/oidc.php` | root | OIDC discovery / JWKS |

| Middleware alias | Class | Role |
|---|---|---|
| `iam.admin_auth` | `AdminAuthenticate` | bearer-token admin auth |
| `iam.can` | `AuthorizeIamPermission` | PDP authorization (`iam.can:iam:<permission>`) |
| `iam.idempotency` | `IdempotencyKey` | dedupe writes via `Idempotency-Key` |

## Key environment variables

| Variable | Purpose |
|---|---|
| `IAM_RUN_MIGRATIONS` | Auto-load migrations (default true) |
| `IAM_OAUTH_ENCRYPTION_KEY` | base64 32-byte OAuth code/refresh key |
| `IAM_ADMIN_AUDIENCE` | Expected `aud` of admin tokens (fail-closed) |
| `IAM_DIRECTORY_ENABLED` | Enable directory sync/test triggers |

## Next

- [Configuration](/operations/configuration) — the prose version with every section.
- [Least-privilege & SoD](/best-practices/least-privilege-and-sod) — using these thresholds.
- [Database schema](/reference/database-schema) — the tables behind it all.
