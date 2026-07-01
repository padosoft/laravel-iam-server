---
title: "02 · Configure the essentials"
description: "Publish config/iam.php, set the token issuer, understand how the ES256 signing keys are generated, set the OAuth encryption key, handle the Windows OpenSSL gotcha, and toggle optional modules."
---

# Step 02 · Configure the essentials

**Goal:** publish the config, set the **issuer**, understand the **signing keys**, and know which knobs
matter. For a local SQLite lab this is a short step — most defaults are sensible and secrets are derived
from `APP_KEY` in dev.

::: callout info "Where you are" icon:map-pin
Step 2 of 8. You have a booted server with the schema migrated. Now you set the few values the IdP needs to
sign and issue tokens.
:::

## 1. Publish the config files

```bash
php artisan vendor:publish --tag="laravel-iam-server-config"
```

This writes two files:

| File | Holds |
|---|---|
| `config/iam.php` | identity, **tokens**, **oauth**, admin API prefix, **crypto/keys**, audit, observability, module toggles |
| `config/iam-governance.php` | governance feature gates, SoD toxic-combinations, least-privilege thresholds |

You don't have to edit anything to make decisions work locally — but you should understand the four things
below. Full key-by-key prose is in [Configuration](/operations/configuration).

## 2. Set the token issuer

The **issuer** (`iss`) is the identity of *your* IdP — it is stamped into every token and checked on
verification. It lives at `tokens.issuer` in `config/iam.php` and reads the `IAM_ISSUER` env var, defaulting
to your app's URL (`app.url`):

```php
// config/iam.php
'tokens' => [
    'issuer' => env('IAM_ISSUER'), // default: app.url
    'access_ttl' => 900,
    'signing_alg' => 'ES256',
    // ...
],
```

For a local lab you can leave it unset (it falls back to `APP_URL`), or pin it explicitly in `.env`:

```dotenv
IAM_ISSUER=http://localhost:8000
```

::: callout warning "The issuer must be stable and match at verify time" icon:alert-triangle
Tokens are verified against this exact string (`iss`). If you sign a token with one issuer and verify with
another, verification **fails** (fail-closed). Pick the URL your server is actually reached at and keep it
consistent between issuing and verifying. In production it is your real HTTPS IdP host.
:::

## 3. Understand the signing keys (nothing to run)

Access tokens and `id_token`s are signed with **ES256** using **rotating signing keys** stored in the
`iam_signing_keys` table. You do **not** run a "generate keys" command: the first time the server needs to
sign a token it creates an EC P-256 key pair and persists it, then publishes the public half at the JWKS
endpoint so clients can verify offline. Rotation is handled for you.

::: callout warning "Windows / Herd: OpenSSL config gotcha" icon:key-round
Generating an EC key with `openssl_pkey_new` needs an OpenSSL config file, which is sometimes missing on
Windows/Herd — you'd see a keygen error the first time a token is signed. The fix is to point IAM at a
minimal config. Create a tiny file and reference it in `config/iam.php`:
```php
// config/iam.php  →  crypto section
'crypto' => [
    'openssl_config' => env('IAM_OPENSSL_CONF'),  // path to an openssl.cnf
    // ...
],
```
Set the path via `.env`:
```dotenv
IAM_OPENSSL_CONF=C:\\xampp\\php\\extras\\openssl\\openssl.cnf
```
A file whose first line is `[req]` is enough for EC keygen. On Linux/macOS you normally don't need this.
:::

## 4. OAuth encryption key (dev vs prod)

`oauth.encryption_key` encrypts authorization codes and refresh tokens at rest. In **dev** it is derived
from `APP_KEY` automatically if you leave it empty — fine for this tutorial. In **production** set an
explicit base64 32-byte key:

```dotenv
# production only — base64 of 32 random bytes
IAM_OAUTH_ENCRYPTION_KEY=
```

You can generate one with `php -r "echo base64_encode(random_bytes(32)).PHP_EOL;"`.

## 5. Toggle optional modules

The governance features are gated with sensible, **privacy-by-default** defaults in
`config/iam-governance.php`:

```php
'features' => [
    'access_review'   => ['default' => 'on',  'permission' => 'iam:access_review.manage'],
    'access_request'  => ['default' => 'off', 'permission' => 'iam:access_request.use'],  // off by default
    'pim'             => ['default' => 'off', 'permission' => 'iam:pim.activate'],
    'sod'             => ['default' => 'detect'],   // observe, don't block
    'least_privilege' => ['default' => 'on',  'permission' => 'iam:least_privilege.view'],
    'anomaly_detection' => ['default' => 'on','permission' => 'iam:anomaly.view'],
],
```

You don't need to change these now. Just note: **`access_request` is `off` by default** — we turn it on only
if you try the self-service access-request flow later. The optional `directory` module is likewise off
(`IAM_DIRECTORY_ENABLED=false`) until you install and enable `laravel-iam-directory`.

## 6. Clear config cache after edits

Whenever you edit a config file or `.env`, clear the cache so the app picks it up:

```bash
php artisan config:clear
```

::: callout success "✅ Checkpoint" icon:check
```bash
php artisan tinker
```
```php
>>> config('iam.tokens.issuer');
=> "http://localhost:8000"      // your value, not the default
```
If you see your issuer, the config is published and loaded. Type `exit`.
:::

::: callout warning "If it fails" icon:alert-triangle
- **`config('iam.tokens.issuer')` is `null`** → you didn't publish the config, or didn't
  `php artisan config:clear` after editing. Re-run the publish command.
- **`openssl_pkey_new(): Failed...` when a token is signed later** → apply the Windows OpenSSL fix in
  section 3.

More in [Troubleshooting](/tutorial/troubleshooting).
:::

## What you just did

::: steps
1. **Published** `config/iam.php` and `config/iam-governance.php`.
2. **Set the issuer** — the identity of your IdP, stamped into and verified on every token.
3. **Learned** that ES256 signing keys are auto-created in `iam_signing_keys` (no command to run), plus the
   Windows OpenSSL fix.
4. **Reviewed** the OAuth encryption key and the privacy-by-default module gates.
:::

**Next:** create your first users and declare permissions and roles.

**[→ Step 03 · First users, roles & permissions](/tutorial/03-first-users-roles)**

---

Deeper references: [Configuration](/operations/configuration) ·
[Permissions & config](/reference/permissions-and-config) · [OAuth2 & OIDC](/architecture/oauth-oidc)
