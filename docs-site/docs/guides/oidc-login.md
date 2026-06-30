---
title: OIDC login
description: The OpenID Connect layer — discovery, JWKS, id_token issuance on an MIT base, federated identities, and how a consuming app logs users in with laravel-iam-client.
---

# OIDC login

On top of OAuth2, the server exposes an **OpenID Connect** layer (`src/Domain/OAuth/Oidc/`) so apps get a
standard identity protocol: discovery, JWKS, and signed `id_token`s. The base is **MIT** (steverhoades) —
never AGPL.

## Motivation

OAuth2 issues *access* tokens (authorization). OIDC adds an *identity* token (`id_token`) and a standard
discovery document, so any OIDC-compliant client can log in against your server without bespoke wiring.

## Discovery & JWKS

The provider publishes the standard endpoints at the application root:

```bash
curl https://iam.example.com/.well-known/openid-configuration
curl https://iam.example.com/.well-known/jwks.json
```

The discovery document advertises the authorization, token and JWKS URLs; clients fetch JWKS to verify
`id_token` and access-token signatures (ES256) offline.

## The login flow

```mermaid
sequenceDiagram
    participant App as Consuming app
    participant Client as laravel-iam-client
    participant IdP as laravel-iam-server
    App->>Client: redirect to login
    Client->>IdP: authorization-code + PKCE
    IdP-->>Client: id_token + access_token
    Client->>IdP: fetch JWKS (cached)
    Client->>Client: verify id_token signature & claims
    Client-->>App: authenticated user (claims)
```

In a consuming app you do **not** implement this by hand — install
[`laravel-iam-client`](https://doc.laravel-iam-client.padosoft.com), which handles the redirect, the PKCE
exchange, JWKS verification and claim mapping, then exposes the authenticated user to your app.

## Federated identities

A user can authenticate through an upstream provider; the link is stored in `iam_federated_identities`
(`src/Domain/Identity/Federation/`). Configure social/federated login by adding
[Socialite](https://laravel.com/docs/socialite) (a `suggest` dependency) as the backend — the IdP records
which provider proved the identity and at what assurance level.

## What's in the id_token

The `id_token` carries standard OIDC claims plus the subject and the assurance level reached at
authentication, which the [PDP can require step-up against](/concepts/assurance-aal). It is signed with the
same rotating ES256 keys as access tokens.

::: callout warning "Verify, don't trust" icon:shield
Always verify the `id_token` signature against JWKS and check `iss`, `aud` and `exp` before trusting any
claim. `laravel-iam-client` does this for you; if you integrate a non-PHP client, use one of the SDKs
([Node](https://doc.laravel-iam-node.padosoft.com), [Rust](https://doc.laravel-iam-rust.padosoft.com)),
which are fail-closed.
:::

## Next

- [Sessions & step-up](/guides/sessions-and-step-up) — revocable server-side sessions and AAL.
- [OAuth2 clients & PKCE](/guides/oauth-clients) — the grant flows beneath OIDC.
- [Assurance levels](/concepts/assurance-aal) — how authentication strength feeds decisions.
