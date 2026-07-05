# private_key_jwt — asymmetric client auth, no shared secret (step by step)

By default a confidential client authenticates with a **shared secret** (`client_secret`) — see
[Application credentials & lifecycle](/guides/application-credentials). **`private_key_jwt`** (RFC 7523 /
OpenID Connect Core §9) is an **optional, stronger alternative**: the client keeps a **private key**,
registers only its **public** key with IAM, and proves itself at each token request by **signing a short
assertion**. IAM verifies the signature with the public key. **Nothing secret ever leaves the app.**

::: callout info "Is it mandatory? No." icon:info
It is **100% optional and per-client**. The default (a shared `client_secret`) keeps working exactly as
before. You choose `private_key_jwt` for a given app when you want *no shared secret to store, rotate, or
leak* — typically machine-to-machine services and regulated environments. You can mix: some apps on secrets,
some on `private_key_jwt`.
:::

## Secret vs. private_key_jwt — which to pick

| | Shared secret (default) | `private_key_jwt` |
| --- | --- | --- |
| What the app stores | the `client_secret` (a bearer credential) | its **private key** |
| What IAM stores | a **hash** of the secret | the app's **public** key (JWKS) |
| A leak of IAM's DB exposes… | nothing usable (it's hashed) | nothing (only a public key) |
| A leak of the app's config exposes… | the secret → impersonation | the private key → impersonation (so protect it) |
| Rotation | rotate the secret (grace + self-fetch) | publish a new public key, no shared value to sync |
| Setup effort | lowest | one keypair + registering the public key |

## What IAM supports

- **Algorithm:** `ES256` (ECDSA P-256) only — advertised in discovery as
  `token_endpoint_auth_signing_alg_values_supported: ["ES256"]`. No `alg: none`, no downgrade.
- **Auth method:** `private_key_jwt` — advertised in `token_endpoint_auth_methods_supported`.
- **Every check is fail-closed:** signature against the registered key · `iss === sub ===` the client_id ·
  `aud` names *this* token endpoint · not expired / not-before · bounded lifetime
  (`IAM_OAUTH_CLIENT_ASSERTION_MAX_LIFETIME`, default 300s) · `jti` single-use (replay-protected).

---

## Step 1 — generate a key pair (app side, command)

On the app's machine (or CI secret store), run two openssl commands. **The private key never leaves here.**

```bash
# private key — keep it secret, on the app only
openssl ecparam -name prime256v1 -genkey -noout -out client-private.pem
# public key — this is what you register in IAM
openssl ec -in client-private.pem -pubout -out client-public.pem
```

## Step 2 — turn the public key into a JWK

IAM registers the public key as a **JWK** (a JSON representation). You have **three ways** — pick one:

**a) From the console UI (no command):** in Applications → **Register app**, expand **"Use private_key_jwt"**,
paste the contents of `client-public.pem`, set a `kid` (e.g. `k1`), and click **Add public key to manifest**.
The console fills in `auth.token_endpoint_auth_method` + `auth.jwks` for you. *(Nothing to compute by hand.)*

**b) With the ready artisan command** (server side):

```bash
php artisan iam:jwk client-public.pem --kid=k1
# → {"kty":"EC","crv":"P-256","x":"…","y":"…","kid":"k1","alg":"ES256","use":"sig"}
# add --jwks to print a full {"keys":[…]} set ready to paste into auth.jwks
```

**c) By hand** — only if you must: base64url-encode the EC point's `x`/`y` coordinates into the JWK above.
(Use a or b instead.)

## Step 3 — register the app with `private_key_jwt`

Put the JWK in the manifest's `auth` block (option **a** did this for you):

```json
{
  "schema": "laravel-iam.manifest.v2",
  "app":   { "key": "billing", "name": "Billing", "type": "service" },
  "auth":  {
    "client_type": "confidential",
    "token_endpoint_auth_method": "private_key_jwt",
    "jwks": { "keys": [ { "kty": "EC", "crv": "P-256", "x": "…", "y": "…", "kid": "k1", "alg": "ES256" } ] }
  },
  "permissions": [ { "key": "invoices.read", "risk": "low" } ]
}
```

Apply it — **from the console** (Register app → Submit → Approve → Apply) **or** by command
(`php artisan iam:manifest:apply billing.json --approve`). The client is created **with no secret**.

## Step 4 — the app signs an assertion (automatic, app side)

::: callout warning "\"Sign an assertion\" — what it means, and why there's no UI button for it" icon:key-round
A **client assertion** is a tiny JWT the app builds and **signs with its private key** on every token
request. Signing **can only happen where the private key lives — inside the app — never in the IAM console**
(IAM only has the public key, by design). So there is *no UI button and no server artisan command to "sign"*:
signing is the **app's job at runtime**, and the official SDKs do it for you automatically.
:::

**With an SDK (recommended — you write no crypto):** configure the private key instead of a secret and the
SDK builds, signs, and refreshes everything:

```dotenv
# consuming app .env (laravel-iam-client / node / rust)
IAM_CLIENT_ID=cli_billing
IAM_CLIENT_PRIVATE_KEY=/secrets/client-private.pem   # path or inline PEM
IAM_CLIENT_PRIVATE_KEY_KID=k1
```

See [SDK authentication modes](/guides/sdk-authentication). That's all — the app now authenticates with no
shared secret.

**By hand (only to test/verify):** the assertion is an ES256 JWT with header `{alg:ES256, kid:k1}` and claims
`iss=sub=cli_billing`, `aud=https://your-iam.example.com/oauth/token`, a unique `jti`, and a short `exp`.
POST it:

```http
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer
&client_assertion=<the signed JWT>
```

No `client_id`/`client_secret` in the body — both are derived from (and proven by) the assertion. IAM returns
an access token.

## Environment variables

| Variable | Side | Regulates | Default |
| --- | --- | --- | --- |
| `IAM_OAUTH_CLIENT_ASSERTION_MAX_LIFETIME` | **server** | reject an assertion whose lifetime (`exp−iat`) exceeds this (seconds); caps a stolen assertion's window | `300` |
| `IAM_CLIENT_PRIVATE_KEY` | **app** | the ES256 private key (PEM path or inline) — presence switches the SDK to private_key_jwt | — |
| `IAM_CLIENT_PRIVATE_KEY_KID` | **app** | the `kid` written into the assertion header | — |

There is **no server env to "enable" private_key_jwt globally** — it's turned on per client by the manifest's
`token_endpoint_auth_method`. Clients without it keep using their secret.

## Security notes

- **ES256 only**; `aud`-bound (an assertion for another server's endpoint is rejected); `jti` **single-use**
  (a replay within its lifetime is rejected); fail-closed on anything malformed/expired.
- **Key rotation:** add a new public key (new `kid`) to the JWKS, switch the app to sign with it, then drop
  the old key. No downtime, no shared secret to coordinate.
- **Protect the private key** like any secret (a secrets manager / KMS, not the repo).

## Next

- [SDK authentication modes](/guides/sdk-authentication) — the app-side config for every SDK.
- [End-to-end onboarding](/guides/onboarding-end-to-end) — the full app→user round-trip.
- [Application credentials & lifecycle](/guides/application-credentials) — the shared-secret alternative.
