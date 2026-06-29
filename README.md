<p align="center">
  <img src="art/banner.png" alt="Laravel IAM" width="100%">
</p>

<h1 align="center">Laravel IAM — Server</h1>

<p align="center">
  <strong>A self-hostable Identity &amp; Authorization control plane for Laravel.</strong><br>
  An OAuth2 / OIDC identity provider, a RBAC + ABAC + ReBAC policy decision point, tamper-evident audit,
  IGA governance and an admin panel — in one composer package you own.
</p>

<p align="center">
  <a href="https://github.com/padosoft/laravel-iam-server/actions/workflows/tests.yml"><img src="https://img.shields.io/github/actions/workflow/status/padosoft/laravel-iam-server/tests.yml?branch=main&style=flat-square&label=tests" alt="Tests"></a>
  <a href="https://packagist.org/packages/padosoft/laravel-iam-server"><img src="https://img.shields.io/packagist/v/padosoft/laravel-iam-server.svg?style=flat-square" alt="Latest Version on Packagist"></a>
  <a href="https://packagist.org/packages/padosoft/laravel-iam-server"><img src="https://img.shields.io/packagist/dt/padosoft/laravel-iam-server.svg?style=flat-square" alt="Total Downloads"></a>
  <a href="https://packagist.org/packages/padosoft/laravel-iam-server"><img src="https://img.shields.io/packagist/php-v/padosoft/laravel-iam-server.svg?style=flat-square" alt="PHP Version"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square" alt="License"></a>
</p>

---

## Why this package

Most teams end up with authorization scattered across every app: a `spatie/permission` table here, a pile of
`Gate::define()` closures there, hand-rolled OAuth somewhere else, and no idea who can do what or who decided
it. Renting an IdP (Auth0, Okta, Entra) fixes login but leaves *authorization* — and your audit trail — off
in someone else's cloud, metered per MAU.

**`laravel-iam-server` is the control plane you host yourself.** It is at once:

- an **identity provider** — OAuth2 (`league/oauth2-server`) + an OIDC layer, with sessions you can revoke;
- a **policy decision point (PDP)** — one deterministic engine that answers *"can subject X do permission Y
  on resource Z?"* with **RBAC + ABAC + ReBAC**, **deny-overrides**, **fail-closed**, and a citable
  explanation;
- a **tamper-evident audit log** — every mutation hash-chained and verifiable, exportable to your SIEM;
- an **identity governance (IGA)** suite — access reviews, access requests/approvals, least-privilege
  recommendations, SoD;
- an **admin panel** — a React console driven entirely through the Admin API (no UI ever touches the DB).

Apps stop owning authorization logic. They **declare** their permissions/roles/scopes in a *manifest*, and
ask the PDP. You get one place to see and prove every access decision.

## Features

- **Deterministic PDP** — `NativeSqlEngine` evaluates RBAC + ABAC (attribute conditions) + ReBAC
  (relationship lookups: `listSubjects` / `listResources`) in one pass, deny-overrides, fail-closed. Every
  `Decision` carries a `decision_id`, the matched policies and a human-readable `explanation` you can cite in
  audit.
- **Application Registry + manifests** — apps submit a manifest of their permissions/roles/scopes/conditions;
  it is **validated, diffed, approved, applied and rollback-able**. The core hardcodes nothing.
- **Full OAuth2 + OIDC IdP** — authorization-code/PKCE, client-credentials, refresh (encrypted), JWKS, an OIDC
  layer on an **MIT** base (never AGPL). Bring your own login backend (Fortify, Socialite, passkeys).
- **Tamper-evident audit** — hash-chained events (`AuditChainAppender` / `AuditChainVerifier`), SIEM export,
  webhooks/outbox, and GDPR crypto-shredding / legal-hold for PII.
- **Identity governance (IGA)** — access-review campaigns, access-request approval flows, least-privilege
  recommendations, separation-of-duties, anomaly signals — each gated per layer/app/role/user via a feature
  scope.
- **Assurance / step-up** — NIST 800-63B assurance levels; the PDP can require step-up (AAL2) for critical
  actions.
- **Admin API + panel** — every admin route is documented in `resources/openapi.yaml` (enforced by a test),
  protected by the `iam.can` permission middleware, with idempotency keys on writes.
- **Observability** — health/readiness endpoints and a pluggable tracer (`NullTracer` / `LogTracer`).

## Use cases

- **Be your organization's IdP.** Run OAuth2/OIDC login for all your apps, on infrastructure you control.
- **Centralize authorization.** Many apps, one PDP: each asks `check()` instead of re-implementing roles.
- **Pass an audit.** Hash-chained, verifiable history + access reviews and SoD give you the evidence
  compliance asks for.
- **Escape scattered gates.** Migrate apps off ad-hoc `Gate`/`spatie` permissions onto declared manifests
  (see the [migration bridge](https://github.com/padosoft/laravel-iam-bridge-spatie-permission)).

## Web Admin Panel

A React + Vite + Tailwind console, driven **only** through the Admin API.

![Dashboard (dark)](art/screenshots/laravel-iam-webadmin-Dashboard-Dark.png)
<p align="center"><em>Dashboard — posture at a glance.</em></p>

| Applications & manifests | Audit trail |
| --- | --- |
| ![Applications](art/screenshots/laravel-iam-webadmin-Applications.png) | ![Audit](art/screenshots/laravel-iam-webadmin-Audit.png) |

| Roles & permissions | Access reviews |
| --- | --- |
| ![Roles and permissions](art/screenshots/laravel-iam-webadmin-Roles-and-Permissions.png) | ![Access reviews](art/screenshots/laravel-iam-webadmin-Access-reviews.png) |

| Policy playground | Anomalies |
| --- | --- |
| ![Policy playground](art/screenshots/laravel-iam-webadmin-Policy-Playground.png) | ![Anomalies](art/screenshots/laravel-iam-webadmin-Anomalies.png) |

> The full set of screens (users, sessions & tokens, organizations, events & webhooks, settings…) lives in
> [`art/screenshots/`](art/screenshots/).

## Installation

```bash
composer require padosoft/laravel-iam-server
```

**Requirements:** PHP **8.3+**, Laravel **13**. A database (MySQL/PostgreSQL/SQLite).

Publish config and run migrations:

```bash
php artisan vendor:publish --tag="laravel-iam-server-config"
php artisan migrate
```

The service provider auto-registers the Admin API, OAuth and OIDC routes, and the `iam.can` /
`iam.admin_auth` / `iam.idempotency` middleware.

## Quick start

### 1. Register an application and its manifest

Each consuming app declares what it needs. A manifest lists permissions/roles (slugs are immutable
`app_key:permission`):

```jsonc
{
  "app_key": "warehouse",
  "permissions": [
    { "key": "warehouse:stock.read",   "label": "Read stock" },
    { "key": "warehouse:stock.adjust", "label": "Adjust stock",
      "condition": { "attr": "amount", "op": "<=", "value": 1000 } }
  ],
  "roles": [
    { "key": "warehouse:operator", "permissions": ["warehouse:stock.read", "warehouse:stock.adjust"] }
  ]
}
```

Submit it through the Admin API (`POST /manifests`), then **approve** and **apply** it — the registry
validates and diffs before anything changes.

### 2. Ask the PDP

The decision point is the only authority on allow/deny. Build a `DecisionQuery` and call the engine:

```php
use Padosoft\Iam\Domain\Authorization\Pdp\NativeSqlEngine;
use Padosoft\Iam\Domain\Authorization\Pdp\DecisionQuery;
use Padosoft\Iam\Contracts\Support\SubjectRef;

$decision = app(NativeSqlEngine::class)->decide(new DecisionQuery(
    subject: new SubjectRef('user', '42'),
    permission: 'warehouse:stock.adjust',
    organizationId: 'org_123',
    context: ['amount' => 500],   // evaluated by the ABAC condition above
    explain: true,
));

$decision->allowed;        // bool — deny-overrides, fail-closed
$decision->decisionId;     // citable in your audit log
$decision->explanation;    // why it decided this way
$decision->requiresStepUp; // true ⇒ ask the user for AAL2 first
```

### 3. Or over HTTP

```bash
curl -X POST https://iam.example.com/admin/decisions/check \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"subject":"user:42","permission":"warehouse:stock.adjust","context":{"amount":500}}'
```

> In your **consuming** apps you normally don't call the PDP directly — you install
> [`padosoft/laravel-iam-client`](https://github.com/padosoft/laravel-iam-client) and protect routes with its
> `iam.can` middleware / Gate adapter, which caches decisions and verifies JWTs.

## Ecosystem

| Package | Role |
| --- | --- |
| [laravel-iam-contracts](https://github.com/padosoft/laravel-iam-contracts) | Shared interfaces & DTOs — the dependency root |
| **laravel-iam-server** *(this repo)* | The control plane: identity, PDP, OAuth/OIDC, audit, governance, Admin API & panel |
| [laravel-iam-client](https://github.com/padosoft/laravel-iam-client) | Client for apps consuming IAM: OIDC login, JWT/JWKS, `iam.can` middleware, Gate adapter |
| [laravel-iam-ai](https://github.com/padosoft/laravel-iam-ai) | Optional AI module: advisory-only governance (redaction + hallucination guard + audit) |
| [laravel-iam-directory](https://github.com/padosoft/laravel-iam-directory) | Optional directory module: LDAP / Active Directory; SCIM in v2 |
| [laravel-iam-bridge-spatie-permission](https://github.com/padosoft/laravel-iam-bridge-spatie-permission) | Migration bridge from spatie/laravel-permission: scan, shadow mode, decision diffing, cutover |

## Documentation

A docmd doc-site lives in [`docs/`](docs/): start at [`docs/index.md`](docs/index.md), then
[Getting started](docs/getting-started.md), [Concepts](docs/concepts.md), and the subsystem guides —
[Policy Decision Point](docs/pdp.md), [OAuth2 & OIDC](docs/oauth-oidc.md), [Audit](docs/audit.md),
[Governance](docs/governance.md), [Admin API](docs/admin-api.md) and [Admin panel](docs/admin-panel.md).
The full HTTP contract is in [`resources/openapi.yaml`](resources/openapi.yaml).

## Security

Laravel IAM is **fail-closed by design**: default-deny, deny-overrides, and any error resolves to *deny*.
Every mutation is hash-chained and verifiable (`audit/verify-chain`); cross-tenant access returns **404**,
not 403; secrets use envelope encryption and PII is crypto-shreddable. OAuth is `league/oauth2-server` and
the OIDC layer is MIT (never AGPL). Please report security issues to **security@padosoft.com** rather than
opening a public issue.

## License

MIT © [Padosoft](https://www.padosoft.com). See [LICENSE](LICENSE).
