# private_key_jwt — asymmetric client authentication (no shared secret)

`private_key_jwt` (RFC 7523 / OpenID Connect Core §9) lets a confidential client authenticate to the token
endpoint **without any shared secret**. Instead of sending a `client_secret`, the client keeps a **private
key** and registers only its **public key** with IAM; at each token request it proves possession by signing
a short-lived **assertion** (a JWT). IAM verifies the signature against the registered public key.

## Why use it

A shared `client_secret` is a bearer credential: anyone who reads it (a leaked `.env`, a log line, a config
backup) can impersonate the app, and it has to be distributed, stored, rotated and revoked. With
`private_key_jwt`:

- **Nothing secret ever leaves the client.** IAM only stores the *public* key — a leak of IAM's database
  does not expose a client credential.
- **No secret to rotate or self-fetch.** Key rotation is the client publishing a new public key; there is no
  shared value to keep in sync (contrast [Application credentials & lifecycle](/guides/application-credentials)).
- **Replay-resistant.** Each assertion is single-use (`jti`), audience-bound (`aud`) and short-lived (`exp`).

It is the top assurance tier for machine-to-machine (`client_credentials`) and confidential
authorization-code clients. Mobile/SPA public clients do **not** use it — they use Authorization Code + PKCE.

## What IAM supports

- **Algorithm:** `ES256` (ECDSA P-256). Advertised in discovery as
  `token_endpoint_auth_signing_alg_values_supported: ["ES256"]`.
- **Auth method:** `private_key_jwt`, advertised in `token_endpoint_auth_methods_supported`.
- **Verification:** signature against the client's registered JWKS · `iss === sub ===` the client_id · `aud`
  names this token endpoint (or the issuer) · not expired / not before · bounded lifetime
  (`IAM_OAUTH_CLIENT_ASSERTION_MAX_LIFETIME`, default 300s) · `jti` single-use until it expires (replay
  protection). Any failure is a fail-closed `invalid_client`.

## 1. Generate a key pair (client side)

```bash
# private key — keep this on the client, never share it
openssl ecparam -name prime256v1 -genkey -noout -out client-private.pem
# public key
openssl ec -in client-private.pem -pubout -out client-public.pem
```

Publish the public key as a JWK. The registered JWKS is `{"keys":[ <jwk> ]}`, e.g.:

```json
{
  "keys": [
    { "kty": "EC", "crv": "P-256", "x": "…base64url…", "y": "…base64url…", "kid": "k1", "alg": "ES256", "use": "sig" }
  ]
}
```

Give each key a `kid` and put the same `kid` in the assertion header — that's how IAM selects the key,
which makes rotation a matter of adding a new key before removing the old one.

## 2. Register the client with `private_key_jwt`

Declare it in the app **manifest** (recommended — the registry owns the client):

```json
{
  "schema": "laravel-iam.manifest.v2",
  "app": { "key": "billing", "name": "Billing", "type": "service" },
  "auth": {
    "client_type": "confidential",
    "token_endpoint_auth_method": "private_key_jwt",
    "jwks": { "keys": [ { "kty": "EC", "crv": "P-256", "x": "…", "y": "…", "kid": "k1", "alg": "ES256" } ] }
  },
  "permissions": [ { "key": "invoices.read", "risk": "low" } ]
}
```

Apply it (`iam:manifest:apply --approve`, or the console onboarding wizard). The client is created with **no
secret** — it authenticates only with its key.

## 3. Build and send the assertion (client side)

Each token request signs a fresh assertion:

| Claim | Value |
| --- | --- |
| `iss` | the client_id (e.g. `cli_billing`) |
| `sub` | the client_id (same as `iss`) |
| `aud` | the token endpoint URL, e.g. `https://iam.example.com/oauth/token` (the issuer is also accepted) |
| `jti` | a unique id — single-use |
| `iat` | now |
| `exp` | now + a few minutes (≤ `IAM_OAUTH_CLIENT_ASSERTION_MAX_LIFETIME`) |

Header: `alg: ES256`, `kid` matching the registered key. Then POST it:

```http
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&scope=invoices.read
&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer
&client_assertion=<the signed JWT>
```

No `client_id` / `client_secret` needed — both are derived from (and proven by) the assertion. IAM verifies
it and issues the access token exactly as for any other grant.

> The official IAM SDKs (`laravel-iam-client`, `laravel-iam-node`, `laravel-iam-rust`) build and sign this
> assertion for you when you configure a private key instead of a client secret.

## Security notes

- **ES256 only.** IAM rejects `alg: none`, HS256, or any other algorithm — no downgrade.
- **Audience-bound.** An assertion minted for another server's token endpoint is rejected (`aud` mismatch).
- **Single-use.** A replayed `jti` (within its lifetime) is rejected; a stolen assertion is useless after
  its first use and after `exp`.
- **Fail-closed.** A missing, malformed, wrongly-signed, expired or replayed assertion authenticates nobody.
- **Key rotation.** Add the new public key (new `kid`) to the JWKS, switch the client to sign with it, then
  drop the old key. No downtime, no shared secret to coordinate.
