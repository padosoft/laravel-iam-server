---
title: Admin API
description: The complete Admin API surface at /api/iam/v1 — every route grouped by tag, the auth/idempotency middleware, the data envelope, and the OpenAPI contract enforced by a test.
---

# Admin API reference

Base path: **`/api/iam/v1`** (configurable via `iam.admin.route_prefix`). Routes are in `routes/admin.php`;
controllers in `src/Http/Admin/`. The full contract is in
[`resources/openapi.yaml`](https://github.com/padosoft/laravel-iam-server/blob/main/resources/openapi.yaml),
enforced against the registered routes by `OpenApiSpecTest`.

## Conventions

- **Auth** — `iam.admin_auth` (bearer token) + `iam.can:iam:<permission>` (PDP authorization).
- **Writes** — accept an `Idempotency-Key` (`iam.idempotency`).
- **Envelope** — responses are wrapped in `{ "data": ... }`.
- **Errors** — RFC 9457 problem-details; cross-tenant access returns **404**.
- **Secrets** — write-only (encrypted, never returned).

## Health *(unauthenticated)*

| Method | Path |
|---|---|
| GET | `/health` |
| GET | `/ready` |

## Users & sessions

| Method | Path |
|---|---|
| GET | `/users` · `/users/{user}` · `/users/{user}/effective-permissions` |
| POST | `/users/{user}/suspend` · `/users/{user}/reactivate` · `/users/{user}/sessions/revoke-all` |
| GET | `/sessions` · `/sessions/{session}` |
| POST | `/sessions/{session}/revoke` |

## Decisions & relations (PDP)

| Method | Path | Notes |
|---|---|---|
| POST | `/decisions/check` | allow/deny |
| POST | `/decisions/explain` | decision + full explanation |
| POST | `/decisions/list-subjects` | ReBAC: who can access R? |
| POST | `/decisions/list-resources` | ReBAC: what can S access? |
| POST · DELETE | `/relations` | write / revoke a ReBAC tuple (idempotent, audited) |

## Applications & manifests

| Method | Path |
|---|---|
| GET | `/applications` · `/applications/{app}` · `/applications/{app}/manifest` |
| POST | `/applications/{app}/manifests` |
| GET | `/manifests` · `/manifests/{manifest}` · `/manifests/{manifest}/diff` |
| POST | `/manifests/{manifest}/approve` · `/reject` · `/apply` · `/rollback` |

## Governance

| Method | Path |
|---|---|
| GET · POST | `/access-reviews/campaigns` |
| POST | `/access-reviews/campaigns/{campaign}/open` · `/close` |
| GET | `/access-reviews/campaigns/{campaign}/items` |
| POST | `/access-reviews/items/{item}/certify` · `/revoke` |
| GET · POST | `/access-requests` |
| GET | `/access-requests/catalog` |
| POST | `/access-requests/{accessRequest}/approve` · `/reject` |
| GET | `/access-requests/{accessRequest}/steps` |
| POST | `/access-requests/{accessRequest}/steps/{step}/approve` · `/reject` |
| GET | `/recommendations/least-privilege` |

## Groups (ReBAC nesting · M17)

| Method | Path |
|---|---|
| GET · POST | `/groups` |
| GET · PUT · DELETE | `/groups/{group}` |
| GET · POST · DELETE | `/groups/{group}/members` |

Group membership writes the ReBAC `member` tuple so the native resolver sees nesting.

## Federated providers (M17)

| Method | Path | Notes |
|---|---|---|
| GET · POST | `/federated-providers` | `client_secret` write-only |
| GET · PUT · DELETE | `/federated-providers/{provider}` | |
| POST | `/federated-providers/{provider}/test` | connectivity check |

## Directory sources (M17)

| Method | Path | Notes |
|---|---|---|
| GET · POST | `/directory-sources` | `bind_secret` write-only |
| GET · PUT · DELETE | `/directory-sources/{source}` | |
| POST | `/directory-sources/{source}/sync` · `/test` | **409** if the `-directory` module is inactive |

## Policy wizard (M17)

| Method | Path | Notes |
|---|---|---|
| GET | `/policies-wizard/permissions` | |
| POST | `/policies-wizard/preview` | writes nothing |
| POST | `/policies-wizard/commit` | idempotent |

## Webhooks (M17)

| Method | Path | Notes |
|---|---|---|
| GET · POST | `/webhooks` | secret write-only |
| GET · PUT · DELETE | `/webhooks/{subscription}` | |
| POST | `/webhooks/{subscription}/test` | |
| GET | `/webhooks/{subscription}/deliveries` | |
| POST | `/webhooks/deliveries/{delivery}/replay` | DLQ replay |

## Metrics (M17)

| Method | Path |
|---|---|
| GET | `/metrics/decisions` · `/metrics/grants` · `/metrics/audit` |

Read-only, tenant-scoped, bounded aggregations.

## Audit

| Method | Path |
|---|---|
| GET | `/audit/events` |
| POST | `/audit/verify-chain` |

::: callout tip "The contract can't drift" icon:check-check
`OpenApiSpecTest` compares `Router::getRoutes()` against `resources/openapi.yaml` and fails the build if any
admin route is undocumented. The published spec is always accurate to the code.
:::

## Next

- [Securing the Admin API](/best-practices/securing-admin-api) — hardening this surface.
- [Decision contract](/reference/decision-contract) — the `/decisions/*` response shape.
- [PHP API](/reference/php-api) — the in-process equivalents.
