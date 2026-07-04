# SDK authentication modes

The official IAM SDKs talk to the PDP (`/decisions/check`) and verify tokens against the JWKS. Each sends an
`Authorization: Bearer` on decision calls; how it obtains that bearer is the **authentication mode**. All
server-side SDKs support the same three, in this order of precedence.

| Mode | What the app holds | How it authenticates | When to use |
|---|---|---|---|
| **`private_key_jwt`** | an ES256 **private key** | signs a short-lived assertion per token request; IAM verifies it against the registered **public** JWKS — no shared secret ever sent | strongest; long-lived services, regulated environments |
| **self-managed `client_credentials`** | `client_id` + `client_secret` | mints/refreshes the token itself and **auto-follows secret rotation** via self-fetch during the grace | services that use a shared secret but want zero-touch rotation |
| **static token** | a pre-issued bearer token | sends it as-is | simplest; short-lived jobs, quick starts |

Each maps to a server feature:

- `private_key_jwt` → [private_key_jwt](/guides/private-key-jwt) (register the public JWKS; RFC 7523).
- `client_credentials` + self-fetch → [Application credentials & lifecycle](/guides/application-credentials)
  (enable `IAM_OAUTH_CLIENT_SELFFETCH=true`).
- static token → any service token you mint out of band.

## Per-SDK configuration

- **[laravel-iam-client](https://github.com/padosoft/laravel-iam-client)** (PHP/Laravel) — `config/iam-client.php`:
  `http.token` (static) · `http.client_id` + `http.client_secret` (client_credentials) · `http.client_id` +
  `http.private_key` (+ `http.private_key_kid`) for private_key_jwt.
- **[laravel-iam-node](https://github.com/padosoft/laravel-iam-node)** (TypeScript) — `IamClient` config:
  `token` · `clientId`+`clientSecret` · `clientId`+`privateKey` (+`privateKeyKid`).
- **[laravel-iam-rust](https://github.com/padosoft/laravel-iam-rust)** (async + blocking) — builder:
  `.token(…)` · `.client_id(…).client_secret(…)` · `.client_id(…).private_key(pem)` (`.private_key_kid(…)`).
- **[laravel-iam-react-native](https://github.com/padosoft/laravel-iam-react-native)** — a **public** client:
  no shared secret and no `private_key_jwt`; obtain the user's token via Authorization Code + **PKCE** and
  refresh it.

Every SDK is **fail-closed**: if no valid bearer can be produced, no `Authorization` header is sent and the
PDP denies.

## Next

- [private_key_jwt](/guides/private-key-jwt) — the asymmetric flow in depth.
- [Application credentials & lifecycle](/guides/application-credentials) — secret rotation & self-fetch.
- [Ask the PDP](/guides/ask-the-pdp) — what the SDKs call once authenticated.
