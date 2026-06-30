---
title: Deployment
description: Running laravel-iam-server in production — database choice, key material and rotation, queues for the outbox, scheduled audit verification, health checks, rate limits and hardening the Admin API.
---

# Deployment

The server is a normal Laravel package, so it deploys like any Laravel app — but it's an IAM control plane,
so a few things deserve extra care.

## Database

Use **MySQL** or **PostgreSQL** in production (SQLite is fine for dev/CI). The IAM tables carry your identity
and audit data — back them up, and treat the audit tables as append-only (never edit rows; it breaks the
[hash-chain](/concepts/tamper-evident-audit)).

## Key material

::: steps
1. **OAuth encryption key** — set `IAM_OAUTH_ENCRYPTION_KEY` (base64, 32 bytes). Don't rely on the
   APP_KEY-derived dev default.
2. **Signing keys** — ES256 keys in `iam_signing_keys` sign tokens; rotate them periodically (new public key
   is published in JWKS before signing with it, so in-flight tokens keep verifying).
3. **Crypto backend** — back `LocalKeyProvider` with a real KMS in production (AWS KMS / Secrets Manager via
   the `aws/aws-sdk-php` suggest dependency).
4. **Admin audience** — set `IAM_ADMIN_AUDIENCE` so admin tokens are audience-pinned (fail-closed).
:::

## Queues for the outbox

Webhook/event delivery uses a [transactional outbox](/guides/webhooks-and-events) dispatched
asynchronously — run a queue worker (and Horizon if you use it) so deliveries flow:

```bash
php artisan queue:work --queue=default
```

## Schedule the maintenance commands

```php
// app/Console/Kernel.php
$schedule->command('iam:audit:verify')->hourly();          // tamper-evidence stays green
$schedule->command('iam:audit:checkpoint')->daily();       // cheaper future verification
$schedule->command('iam:least-privilege:scan')->daily();   // fresh recommendations
$schedule->command('iam:reviews:remind')->dailyAt('09:00');// nudge reviewers
```

## Health checks

Wire your orchestrator's probes to the unauthenticated endpoints (same prefix as the Admin API):

```bash
GET /api/iam/v1/health   # liveness
GET /api/iam/v1/ready    # readiness (dependencies reachable)
```

See [Observability](/operations/observability).

## Hardening checklist

| Item | Action |
|---|---|
| Token transport | bearer header only; TLS everywhere |
| Audience pinning | `IAM_ADMIN_AUDIENCE` set |
| Rate limits | tune `iam.admin.rate_limit` / `iam.oauth.rate_limit`, keep a ceiling |
| Secrets | write-only across the API; rotate, never read back |
| Tenant scope | preserved in any custom code (404, not 403) |
| Audit verification | scheduled + alerted on break |
| Backups | DB backups + SIEM export for retention |

## The admin panel

The React panel is a separate static app that talks **only** to this API. Deploy it behind the same TLS and
auth boundary; it gets no special database access. See [Admin panel](/operations/admin-panel).

::: callout warning "Don't migrate over a live chain carelessly" icon:database
When upgrading, run migrations in a maintenance window and verify the audit chain before and after. Never
hand-edit IAM tables to "fix" data — go through the Admin API so validation, idempotency and audit apply.
:::

## Next

- [Configuration](/operations/configuration) — every key you'll set here.
- [Observability](/operations/observability) — health, readiness, tracing.
- [Securing the Admin API](/best-practices/securing-admin-api) — the hardening detail.
