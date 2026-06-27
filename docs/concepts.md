---
title: Concepts
description: The mental model behind the IAM server — the problem, subjects, manifests, the PDP, and the fail-closed contract.
---

# Concepts

## The problem

Authorization tends to rot. Each app grows its own roles table, its own `Gate` closures, its own copy of
"who is an admin". Logins might be centralized (an external IdP) but *decisions* are not — so nobody can
answer "who can adjust stock, and who granted them that?" without reading code in five repositories.

## The mental model

Laravel IAM separates the **decision** from the **enforcement** and from the **declaration**:

- **Declaration** — each application ships a *manifest* of its permissions, roles, scopes and conditions.
- **Decision** — a single **Policy Decision Point (PDP)** evaluates a request against those policies.
- **Enforcement** — apps (via `laravel-iam-client`) ask the PDP and allow/deny accordingly. They never
  re-implement the rules.

## Core entities

::: card "Subject"
A `SubjectRef` is a `type:id` value object (`user:42`, `service_account:7`, `external_group:eng`). It is the
single way every part of the system refers to *who* is acting.
:::

::: card "Permission & role"
Permissions are immutable slugs `app_key:permission` (e.g. `warehouse:stock.adjust`). Roles bundle
permissions. Both are introduced through an application's manifest, never hardcoded in the core.
:::

::: card "Decision"
A `DecisionQuery` (subject + permission + org + context + AAL) goes in; a `Decision` (allowed, decision_id,
matched policies, explanation, requiresStepUp) comes out — deterministic and citable in audit.
:::

## Example: an attribute condition

A manifest can attach an ABAC condition to a permission:

```jsonc
{ "key": "warehouse:stock.adjust",
  "condition": { "attr": "amount", "op": "<=", "value": 1000 } }
```

The caller passes `context: ['amount' => 500]`; the PDP's `ConditionEvaluator` checks it. `amount = 5000`
would be denied even for a user who otherwise holds the permission.

## Anti-patterns

::: callout danger "Don't do this"
- **Bypassing the PDP** with a local `if ($user->isAdmin())`. The PDP is the only allow/deny authority.
- **Returning 403 for cross-tenant** resources — it confirms the resource exists. Return **404**.
- **Hardcoding permissions** in the server. They belong in the app's manifest.
- **Failing open** on error. Every failure path must deny.
:::

## Why it's built this way

One decision point means one place to reason about, test, explain and audit access. Declaring policies in
manifests keeps the core generic and lets apps evolve their own permissions safely (validated, diffed,
rollback-able). Fail-closed + hash-chained audit means a mistake degrades to "denied and logged", not to a
silent privilege leak.
