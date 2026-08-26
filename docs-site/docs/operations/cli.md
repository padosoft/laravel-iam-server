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

## Policy regression

| Command | Purpose |
|---|---|
| `iam:policy:check {--org=} {--json}` | Evaluate the probes that carry an expected outcome against the current policy; **exits non-zero** on any divergence. The CI gate. |

```bash
php artisan iam:policy:check          # in CI, before a policy change ships
php artisan iam:policy:check --json   # machine-readable for a pipeline
```

A corpus with no expectations **passes and says so**: a gate that passes because
it has nothing to check is worse than no gate, because it looks like one. See
[Blast radius & regression](/guides/blast-radius-and-regression).

## OAuth client credentials

| Command | What it does |
|---|---|
| `iam:rotate-due-secrets` | Rotate the secret of every confidential client that opted into `auto_rotate` and whose interval elapsed (storing the new secret encrypted for one-time self-fetch during the grace), and clear pending ciphertexts whose grace has lapsed. |
| `iam:jwk {pem} {--kid=} {--jwks}` | Convert an EC P-256 **public** key PEM into a JWK (or a full `{"keys":[…]}` set) to paste into a manifest's `auth.jwks` for **private_key_jwt** — so you never hand-compute the `x`/`y` coordinates. |

```bash
php artisan iam:jwk client-public.pem --kid=k1 --jwks
```

See [Application credentials & lifecycle](/guides/application-credentials) and
[private_key_jwt](/guides/private-key-jwt).

## Sessions

| Command | What it does |
|---|---|
| `iam:prune-sessions {--days=}` | Mark idle- and absolute-expired sessions as revoked (reason `idle` / `absolute_expired`), then hard-delete rows revoked beyond the retention window (`IAM_SESSION_RETENTION_DAYS`, override with `--days=`). Keeps `iam_sessions` bounded. |

See [Sessions & step-up](/guides/sessions-and-step-up).

## Idempotency store

| Command | What it does |
|---|---|
| `iam:prune-idempotency {--days=}` | Delete `iam_idempotency_keys` rows older than the retention window (`iam.admin.idempotency_retention_days`, default **7**; override with `--days=`). The replay store has no natural expiry, so without a prune it grows unbounded — schedule this daily. |

```bash
php artisan iam:prune-idempotency            # retention from config (default 7 days)
php artisan iam:prune-idempotency --days=3   # override
```

The stored response body is encrypted at rest (`Crypt` / `APP_KEY`) so the table is never a recoverable
cleartext credential store, but pruning keeps it bounded regardless. See
[Securing the Admin API](/best-practices/securing-admin-api).

## Scheduling

Wire the maintenance commands into Laravel's scheduler (see [Deployment](/operations/deployment)):

```php
$schedule->command('iam:audit:verify')->hourly();
$schedule->command('iam:audit:checkpoint')->daily();
$schedule->command('iam:least-privilege:scan')->daily();
$schedule->command('iam:reviews:remind')->dailyAt('09:00');
$schedule->command('iam:rotate-due-secrets')->daily();   // OAuth secret auto-rotation
$schedule->command('iam:prune-sessions')->daily();       // session expiry sweep + retention
$schedule->command('iam:prune-idempotency')->daily();    // idempotency replay-store retention
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
