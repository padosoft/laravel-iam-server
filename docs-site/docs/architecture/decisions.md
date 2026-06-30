---
title: Architecture decisions (ADR)
description: The load-bearing decisions behind laravel-iam-server — declared manifests, one PDP, deny-overrides + fail-closed, 404-not-403, native ReBAC, league/oauth2-server + MIT OIDC, hash-chain + crypto-shredding, Admin-API-only.
---

# Architecture decisions

A consolidated record of the decisions that shape the package. Each is *Problem → Decision → Consequences*.
They are the same invariants enforced in `CLAUDE.md` and the test suite.

::: collapsible "ADR-1 — Apps declare policy as manifests; the core authors none"
**Problem.** A hardcoded permission catalog couples every app's vocabulary to the server's release cycle.

**Decision.** Applications declare permissions/roles/scopes/conditions as a **manifest**; the Application
Registry validates, diffs, approves, applies and rolls back. The core stores, never authors, policy.

**Consequences.** Apps evolve independently and safely; every change is reviewable and reversible and
audited. The cost — a submission/approval workflow — is exactly the governance authorization needs.
See [Manifests](/concepts/manifests).
:::

::: collapsible "ADR-2 — One PDP evaluates RBAC + ABAC + ReBAC in a single pass"
**Problem.** Three separate models produce three answers and three audit trails a caller must reconcile.

**Decision.** `NativeSqlEngine::decide` evaluates all three and emits one `Decision` with one `explanation`
and one `decisionId`.

**Consequences.** A single citable answer; deny-overrides applied uniformly; no reconciliation bugs. The
engine is more complex, contained behind the `AuthorizationEngine` interface.
See [Authorization models](/concepts/authorization-models).
:::

::: collapsible "ADR-3 — Deny-overrides + fail-closed, with no exceptions"
**Problem.** Authorization code is where an unhandled error must not become an allow, and a stray permit
must not override a deny.

**Decision.** Combine verdicts with deny-overrides (default-deny, monotone in deny); resolve **any** error,
missing data or timeout to deny. The engine returns a decision, never throws one.

**Consequences.** A bug degrades to "denied and logged", never a silent leak. A real outage looks like
"everything denied" — the safe direction, visible in health checks.
See [Deny-overrides & fail-closed](/concepts/deny-overrides-fail-closed).
:::

::: collapsible "ADR-4 — Cross-tenant access returns 404, not 403"
**Problem.** 403 confirms a resource exists, enabling cross-tenant enumeration.

**Decision.** Anything outside the caller's organization returns 404 — identical to a non-existent resource.

**Consequences.** No enumeration oracle across tenants. A forbidden in-tenant action and a cross-tenant one
can look alike — acceptable, since in-tenant authorization is governed separately by the PDP.
See [Multi-tenancy](/concepts/multi-tenancy).
:::

::: collapsible "ADR-5 — Native SQL ReBAC now, external Zanzibar backend later"
**Problem.** Pure-Zanzibar engines (OpenFGA/SpiceDB) scale enormously but add an external dependency most
deployments don't need on day one.

**Decision.** Ship a native SQL resolver with bounded, fail-closed traversal behind the
`AuthorizationEngine` interface (which already exposes `listSubjects`/`listResources`). The external backend
is a v2 swap.

**Consequences.** Self-contained for the common case; a future external backend slots in without touching
the PDP or the manifest contract.
See [ReBAC relationships](/guides/rebac-relationships).
:::

::: collapsible "ADR-6 — league/oauth2-server + a thin MIT OIDC layer (never AGPL)"
**Problem.** Passport is opinionated and session-tied; many OIDC libraries are AGPL.

**Decision.** Build on `league/oauth2-server` (MIT) with a thin MIT OIDC layer; tokens are ES256 JWTs with
JWKS, bound to revocable sessions.

**Consequences.** A permissively-licensed, self-contained IdP with offline verification and immediate
revocation. AGPL OAuth/OIDC code is forbidden.
See [OAuth2 & OIDC](/architecture/oauth-oidc).
:::

::: collapsible "ADR-7 — Hash-chain + crypto-shredding, not an immutable store"
**Problem.** Compliance wants immutability *and* a right-to-erasure; a write-once store can't give both.

**Decision.** Rows are immutable and tamper-evident via a hash-chain; PII is erasable by destroying its
encryption key (crypto-shredding), not by deleting the row. Legal hold suspends shredding.

**Consequences.** Verification stays valid after erasure. The cost is per-scope key management, handled by
the crypto layer.
See [Tamper-evident audit](/concepts/tamper-evident-audit).
:::

::: collapsible "ADR-8 — The Admin API is the only write path; no UI touches the DB"
**Problem.** A UI with direct DB access is a privileged back door that skips authorization, idempotency and
audit.

**Decision.** Every admin operation goes through the Admin API — PDP-authorized (`iam.can`), idempotent on
writes, audited. The React panel is just another API client. Every route is documented in
`resources/openapi.yaml`, enforced by `OpenApiSpecTest`.

**Consequences.** One authorization and audit path for humans and automation alike; no back door. Adding a
route means updating the spec, or the build fails.
See [Securing the Admin API](/best-practices/securing-admin-api).
:::

::: collapsible "ADR-9 — State transitions are TOCTOU-safe under lock"
**Problem.** Read-then-write transitions (approvals, manifest rollback, revocations, campaign close) race:
last-write-wins yields orphan grants or double approvals.

**Decision.** Every such transition runs in `DB::transaction` + `lockForUpdate` + re-check under lock.

**Consequences.** No double-grant, no orphan grant, no lost campaign outcome under concurrency. A small
locking cost on write paths.
:::

## Next

- [Core concepts](/core-concepts) — the invariants these ADRs encode.
- [Architecture overview](/architecture/overview) — the structure they shape.
- [Best Practices](/best-practices/fail-closed-design) — applying them in your own code.
