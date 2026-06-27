---
title: OAuth2 & OIDC
description: The identity provider — league/oauth2-server grants, an MIT OIDC layer, JWKS, encrypted refresh tokens and revocable sessions.
---

# OAuth2 & OIDC

The server is a full identity provider. It lives in `src/Domain/OAuth/` and is built on
[`league/oauth2-server`](https://oauth2.thephpleague.com/) — **not** Passport.

## What's included

- **Grants** (`Grants/`) — authorization-code with PKCE, client-credentials, refresh-token.
- **OIDC layer** (`Oidc/`) — id_token issuance, discovery, JWKS, on an **MIT** base.
- **Token plumbing** (`Token/`, `Entities/`, `Repositories/`, `ResponseTypes/`) — issuing, JWKS exposure,
  introspection.
- **Client auth** (`ClientAuthenticator`) and **encrypted refresh tokens** (`RefreshTokenCrypto`).

::: callout danger "Licensing invariant"
The OIDC layer uses the **MIT** steverhoades base. AGPL code (limosa-io) is **forbidden** in this codebase,
and OAuth must remain `league/oauth2-server`. This is a hard ecosystem rule — see `CLAUDE.md`.
:::

## Routes

OAuth and OIDC routes are registered automatically by the service provider (`routes/oauth.php`,
`routes/oidc.php`): the authorization endpoint, token endpoint, JWKS, and the OIDC discovery document.

## Bring your own login backend

The IdP issues tokens; *how* a user proves who they are is pluggable. The package `suggest`s — but does not
require — login backends:

::: tabs
== tab "Fortify"
```bash
composer require laravel/fortify
```
A native username/password backend.
== tab "Socialite"
```bash
composer require laravel/socialite
```
Federated/social login.
== tab "Passkeys"
```bash
composer require laravel/passkeys
```
WebAuthn / passkeys — satisfies AAL2 for step-up.
:::

## Sessions

Sessions are **server-side and revocable** (`Domain/Identity/Session/`): bound to tokens via a `sid`, with
idle and absolute timeouts, and fail-closed checks. An admin can revoke a single session or all sessions for
a user through the Admin API (`/admin/sessions/...`).

## Assurance

The IdP records the assurance level (AAL) reached at authentication. The PDP can then require step-up for
sensitive permissions — see [Policy Decision Point](pdp.md#step-up).
