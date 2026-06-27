---
title: Home
description: The self-hostable Identity & Authorization control plane for Laravel — IdP, PDP, audit, governance and admin panel.
---

# Laravel IAM — Server

`padosoft/laravel-iam-server` is the **control plane** of the [Laravel IAM](https://github.com/padosoft)
ecosystem: a self-hostable Identity & Authorization platform you install as a composer package.

::: callout tip "One package, five responsibilities"
An OAuth2/OIDC **identity provider**, a deterministic **policy decision point** (RBAC + ABAC + ReBAC), a
**tamper-evident audit** log, an **IGA governance** suite, and a React **admin panel** — all driven through
one Admin API.
:::

## What it gives you

::: card "Identity provider"
OAuth2 on `league/oauth2-server` + an OIDC layer (MIT base), with server-side, revocable sessions.
:::

::: card "Policy Decision Point"
`NativeSqlEngine` answers *"can subject X do permission Y on resource Z?"* — deny-overrides, fail-closed,
with a citable `explanation`.
:::

::: card "Audit & governance"
Hash-chained audit (verifiable, SIEM-exportable) plus access reviews, access requests, least-privilege and
SoD.
:::

## Where to go next

- [Getting started](getting-started.md) — install, migrate, register your first application.
- [Concepts](concepts.md) — the mental model: subjects, manifests, the PDP, fail-closed.
- Subsystems: [PDP](pdp.md) · [OAuth2 & OIDC](oauth-oidc.md) · [Audit](audit.md) · [Governance](governance.md).
- [Admin API](admin-api.md) and the [Admin panel](admin-panel.md).

## Ecosystem

This is the server. Apps that *consume* it use
[`laravel-iam-client`](https://github.com/padosoft/laravel-iam-client); both depend on the shared
[`laravel-iam-contracts`](https://github.com/padosoft/laravel-iam-contracts).
