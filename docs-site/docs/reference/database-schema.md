---
title: Database schema
description: The package migrations and the iam_ tables they create — identity, authorization catalog, keys, OAuth, applications/manifests, audit, governance, ReBAC relations, groups, directory and approval steps.
---

# Database schema reference

Tables are created by the migrations in `database/migrations/`, loaded automatically (toggle with
`iam.run_migrations`). All are prefixed `iam_`. The migrations are the source of truth for exact columns and
indexes; this page lists them by feature. The grouped view is in the [Data model](/architecture/data-model).

## Migrations, in order

| # | Migration | Creates / changes |
|---|---|---|
| 1 | `create_iam_core_tables` | users, organizations and core identity tables |
| 2 | `create_iam_authz_catalog` | permissions, roles, grants (the authorization catalog) |
| 3 | `create_iam_data_keys` | envelope-encryption data keys |
| 4 | `create_iam_signing_keys` | ES256 token-signing keys (rotating) |
| 5 | `create_iam_oauth_clients` | OAuth clients |
| 6 | `create_iam_oauth_grant_tables` | auth codes, access/refresh tokens, scopes |
| 7 | `create_iam_sessions` | server-side, revocable sessions |
| 8 | `create_iam_step_up_challenges` | step-up (AAL2) challenges |
| 9 | `create_iam_federated_identities` | upstream-provider identity links |
| 10 | `add_session_to_oauth_auth_codes` | binds auth codes to a session `sid` |
| 11 | `create_iam_applications_and_manifests` | Application Registry + manifests |
| 12 | `create_iam_audit_tables` | hash-chained events, checkpoints, outbox, PII envelopes |
| 13 | `create_iam_review_tables` | access-review campaigns + items |
| 14 | `create_iam_access_requests` | access requests |
| 15 | `create_iam_idempotency_keys` | idempotency keys for writes |
| 16 | `create_iam_relations_table` | ReBAC tuples `(subject, relation, object)` |
| 17 | `add_relation_to_iam_permissions` | optional `relation` binding on permissions |
| 18 | `create_iam_groups_tables` | groups + membership (writes the `member` tuple) |
| 19 | `create_iam_directory_sources` | directory-source configuration |
| 20 | `create_iam_approval_steps` | approver-chain steps for access requests |

## By subsystem

::: card "Identity & sessions" icon:user
`iam_core_tables`, `iam_sessions`, `iam_step_up_challenges`, `iam_federated_identities`. See
[Sessions & step-up](/guides/sessions-and-step-up).
:::

::: card "Authorization & ReBAC" icon:scale
`iam_authz_catalog` (+ `relation` column), `iam_relations`, `iam_groups_tables`. See
[Authorization models](/concepts/authorization-models) and [ReBAC](/guides/rebac-relationships).
:::

::: card "Keys & OAuth" icon:key-round
`iam_data_keys`, `iam_signing_keys`, `iam_oauth_clients`, `iam_oauth_grant_tables`. See
[OAuth2 & OIDC](/architecture/oauth-oidc).
:::

::: card "Applications & audit" icon:link
`iam_applications_and_manifests`, `iam_audit_tables`. See [Manifests](/concepts/manifests) and
[Tamper-evident audit](/concepts/tamper-evident-audit).
:::

::: card "Governance & infra" icon:clipboard-check
`iam_review_tables`, `iam_access_requests`, `iam_approval_steps`, `iam_idempotency_keys`,
`iam_directory_sources`. See [Access reviews](/guides/access-reviews).
:::

::: callout warning "Treat audit tables as append-only" icon:database
Never `UPDATE`/`DELETE` `iam_audit_tables` rows out of band — it breaks the
[hash-chain](/concepts/tamper-evident-audit) and the tamper-evidence for every later event. Use
crypto-shredding for PII erasure, and go through the Admin API for everything else.
:::

## Next

- [Data model](/architecture/data-model) — the grouped, relational view.
- [Tamper-evident audit](/concepts/tamper-evident-audit) — the audit tables' guarantees.
- [Configuration](/operations/configuration) — `run_migrations` and related settings.
