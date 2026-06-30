---
title: Admin API
description: The HTTP control surface — permission-protected routes, idempotency keys, and an OpenAPI spec enforced by tests.
---

# Admin API

Everything the admin panel does, it does through the **Admin API** — no UI ever touches the database
directly. Routes are in `routes/admin.php`; controllers in `src/Http/Admin/`.

## Authentication & authorization

Each route is protected by two middleware:

- `iam.admin_auth` — authenticates the admin caller (bearer token).
- `iam.can:iam:<permission>` — authorizes via the PDP, e.g. `iam.can:iam:manifests.apply`.

Write routes also accept an **idempotency key** (`iam.idempotency`) so retries don't double-apply.

::: callout warning "Send the token as a bearer header"
Pass the admin token in `Authorization: Bearer …`, never in a query string or a plain-text form field.
:::

## Surface (selected)

| Group | Examples |
| --- | --- |
| Users & sessions | `GET users`, `users/{user}/effective-permissions`, `POST users/{user}/suspend`, `sessions/{session}/revoke` |
| Decisions | `POST decisions/check`, `decisions/explain`, `decisions/list-subjects`, `decisions/list-resources` |
| Applications & manifests | `GET applications`, `POST applications/{app}/manifests`, `manifests/{m}/approve\|apply\|rollback`, `manifests/{m}/diff` |
| Governance | `access-reviews/...`, `access-requests/...`, `recommendations/least-privilege` |
| Groups (M17) | `GET\|POST groups`, `groups/{group}/members`, writes the ReBAC `member` tuple so the native resolver sees nesting |
| Federated providers (M17) | `GET\|POST federated-providers`, `federated-providers/{p}/test` — `client_secret` write-only (encrypted, never returned) |
| Directory sources (M17) | `GET\|POST directory-sources`, `directory-sources/{s}/sync\|test` — `bind_secret` write-only; `409` when the `-directory` module is inactive |
| Policy wizard (M17) | `GET policies-wizard/permissions`, `POST policies-wizard/preview` (writes nothing), `POST policies-wizard/commit` (idempotent) |
| Webhooks (M17) | `GET\|POST webhooks`, `webhooks/{w}/test`, `webhooks/{w}/deliveries`, `POST webhooks/deliveries/{d}/replay` (DLQ) — secret write-only |
| Metrics (M17) | `GET metrics/decisions\|grants\|audit` — read-only, tenant-scoped, bounded aggregations |
| Approver chain (M17) | `POST access-requests/{r}/steps/{s}/approve\|reject` — sequential AND; grant emitted only at the final step |
| Audit | `GET audit/events`, `POST audit/verify-chain` |

## The contract is tested

The complete contract lives in [`resources/openapi.yaml`](https://github.com/padosoft/laravel-iam-server/blob/main/resources/openapi.yaml).

::: callout tip "Spec drift can't sneak in"
`OpenApiSpecTest` compares Laravel's registered admin routes (`Router::getRoutes()`) against the OpenAPI
document and fails the build if any route is undocumented. Adding a route means updating the spec.
:::

## Idempotency

```bash
curl -X POST https://iam.example.com/admin/manifests/{id}/apply \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Idempotency-Key: 7f3c…"     # safe to retry
```
