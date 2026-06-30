---
title: CLI reference
description: The artisan commands shipped by the package — manifest validate/apply/rollback, audit verify/checkpoint/export, access-review open/close/remind, and the least-privilege scan.
---

# CLI reference

The package registers artisan commands under the `iam:` namespace (`src/Console/Commands/`) for CI pipelines
and operations — the offline counterpart to the [Admin API](/reference/admin-api).

## Manifests

| Command | Purpose |
|---|---|
| `iam:manifest:validate {file}` | Validate a manifest JSON without applying it. |
| `iam:manifest:apply {file} {--approve} {--by=}` | Apply a manifest; `--approve` approves gated changes, `--by=` records the actor. |
| `iam:manifest:rollback {app}` | Roll back an application to its previous applied manifest. |

```bash
php artisan iam:manifest:validate warehouse-manifest.json
php artisan iam:manifest:apply    warehouse-manifest.json --approve --by=ci-bot
php artisan iam:manifest:rollback warehouse
```

There is also a `iam:manifest` listing command (`ManifestCommand`) for inspecting registered applications
and manifests.

## Audit

| Command | Purpose |
|---|---|
| `iam:audit:verify {--stream=global}` | Walk the hash-chain and report any break. |
| `iam:audit:checkpoint {--stream=global}` | Seal a stream up to now for cheaper future verification. |
| `iam:audit:export` | Export audit events (SIEM). |

```bash
php artisan iam:audit:verify --stream=global
php artisan iam:audit:checkpoint --stream=global
php artisan iam:audit:export
```

`--stream` accepts `global` or a scope such as an `organization_id`.

## Access reviews

| Command | Purpose |
|---|---|
| `iam:reviews:open {--campaign=}` | Open a campaign (snapshot grants + signals). |
| `iam:reviews:close {--campaign=}` | Close a campaign. |
| `iam:reviews:remind {--campaign=}` | Remind reviewers of pending items. |

```bash
php artisan iam:reviews:open  --campaign=q3-warehouse
php artisan iam:reviews:remind --campaign=q3-warehouse
php artisan iam:reviews:close  --campaign=q3-warehouse
```

## Least-privilege

| Command | Purpose |
|---|---|
| `iam:least-privilege:scan {--org=}` | Produce least-privilege recommendations; `--org=` limits the scope. |

```bash
php artisan iam:least-privilege:scan --org=org_123
```

## Scheduling

Wire the maintenance commands into Laravel's scheduler (see [Deployment](/operations/deployment)):

```php
$schedule->command('iam:audit:verify')->hourly();
$schedule->command('iam:audit:checkpoint')->daily();
$schedule->command('iam:least-privilege:scan')->daily();
$schedule->command('iam:reviews:remind')->dailyAt('09:00');
```

::: callout tip "CI-friendly manifests" icon:terminal
`iam:manifest:validate` is ideal as a pull-request check: fail the build if a proposed manifest is
malformed, before it ever reaches the registry. Pair it with `iam:manifest:apply --approve` in your deploy
job.
:::

## Next

- [Register an application](/guides/register-application) — the manifest workflow these mirror.
- [Audit & compliance](/best-practices/audit-and-compliance) — scheduling verification/export.
- [Admin API reference](/reference/admin-api) — the HTTP equivalents.
