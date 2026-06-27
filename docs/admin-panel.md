---
title: Admin panel
description: The React + Vite + Tailwind console for Laravel IAM — driven entirely through the Admin API.
---

# Admin panel

A React + Vite + Tailwind console that drives the server **only** through the [Admin API](admin-api.md) — it
never reads the database directly.

![Dashboard (dark)](../art/screenshots/laravel-iam-webadmin-Dashboard-Dark.png)

## Screens

::: card "Applications & manifests"
Register apps, review manifest diffs, approve/apply/rollback.
:::

![Applications](../art/screenshots/laravel-iam-webadmin-Applications.png)
![Manifests](../art/screenshots/laravel-iam-webadmin-manifests.png)

::: card "Roles, permissions & policy"
Browse roles and permissions; test decisions live in the policy playground.
:::

![Roles and permissions](../art/screenshots/laravel-iam-webadmin-Roles-and-Permissions.png)
![Policy playground](../art/screenshots/laravel-iam-webadmin-Policy-Playground.png)

::: card "Governance"
Run access-review campaigns, triage access requests, review anomalies.
:::

![Access reviews](../art/screenshots/laravel-iam-webadmin-Access-reviews.png)
![Access requests](../art/screenshots/laravel-iam-webadmin-Access-requests.png)
![Anomalies](../art/screenshots/laravel-iam-webadmin-Anomalies.png)

::: card "Audit, users & sessions"
Inspect the hash-chained audit trail, users (overview, grants, organizations, audit), sessions & tokens,
events & webhooks.
:::

![Audit](../art/screenshots/laravel-iam-webadmin-Audit.png)
![Users](../art/screenshots/laravel-iam-webadmin-Users.png)
![Sessions and tokens](../art/screenshots/laravel-iam-webadmin-Session-e-token.png)
![Events and webhooks](../art/screenshots/laravel-iam-webadmin-Events-e-Webhooks.png)

> All screenshots live in [`art/screenshots/`](https://github.com/padosoft/laravel-iam-server/tree/main/art/screenshots).

## Why API-only

Because the panel is just another Admin API client, every action it performs is authorized by the PDP,
idempotent on writes, and **audited** — there is no privileged back door that skips the same checks your
automation goes through.
