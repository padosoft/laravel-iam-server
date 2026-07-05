# End-to-end: onboard an app, then authorize a real user (step by step)

This is the **whole round-trip**, spelled out for someone doing it for the first time: an application goes
from *not existing in IAM* to a **real user performing an action the PDP allows because IAM decided so**.
Nothing is skipped. Each step says **who does it** and **whether it's a click in the console (GUI) or a
command**.

## The cast

| Who | Does what | Where |
| --- | --- | --- |
| **IAM operator** (you) | onboards the app, creates users, assigns access | the **console** (GUI) |
| **App developer** | writes the manifest, drops the credentials into the app, calls the PDP | the app's repo / `.env` |
| **End user** (e.g. *marco*) | signs in to the app and does something | the app |

## What's GUI vs command

| Step | GUI (console) | Command |
| --- | --- | --- |
| 1. Describe the app (manifest) | ✅ paste in the Register-app editor | write a `.json` file |
| 2. Onboard: submit → approve → apply | ✅ Applications → **Register app** | `iam:manifest:apply file.json --approve` |
| 3. Put credentials in the app | — | edit the app's `.env` |
| 4. App asks the PDP | — | the app's SDK (`iam.can`) at runtime |
| 5. Create a user | ✅ Users → **Create user** | — (no user-create command) |
| 6. Grant the user access | ✅ Users → grants / Roles & Grants | — |
| 7. Verify the decision | ✅ **Decision playground** | `POST /api/iam/v1/decisions/check` |

> **Rule of thumb:** everything an *operator* does is in the GUI. The only "commands" are things the *app
> developer* runs in their own project (or CI), plus the optional `iam:manifest:apply` if you prefer a
> pipeline over clicking.

---

## Step 0 — prerequisites

IAM is deployed and migrated, the role catalog is seeded, and you're signed in to the console as an operator
who can manage applications, users and grants (the first super-admin can do everything). See
[Deploy on Laravel Cloud](/tutorial/09-deploy-on-laravel-cloud).

## Step 1 — describe the app in a manifest

A **manifest** is a small JSON document that declares the app, the permissions it defines, the roles it
offers, and how it authenticates. Example — a `warehouse` service:

```json
{
  "schema": "laravel-iam.manifest.v2",
  "app":   { "key": "warehouse", "name": "Warehouse", "type": "service", "risk_level": "low" },
  "auth":  { "client_type": "confidential", "redirect_uris": ["https://warehouse.example.com/callback"] },
  "permissions": [
    { "key": "stock.read",   "risk": "low" },
    { "key": "stock.adjust", "risk": "medium" }
  ],
  "roles": [
    { "key": "clerk",   "label": "Clerk",   "permissions": ["stock.read"] },
    { "key": "manager", "label": "Manager", "permissions": ["stock.read", "stock.adjust"] }
  ]
}
```

- `type: "service"` → a machine-to-machine client (uses `client_credentials`). Use `"laravel"` for an app
  that logs *human users* in (uses `authorization_code` + `refresh_token`).
- **Permission keys are short** (`stock.read`); IAM namespaces them to `warehouse:stock.read`.
- Want **no shared secret**? Add `"token_endpoint_auth_method": "private_key_jwt"` + a `jwks` — see the
  [private_key_jwt guide](/guides/private-key-jwt). Everything below works the same either way.

## Step 2 — onboard it (submit → approve → apply)

Onboarding is **gated**: a human approves before anything is created. Three sub-steps:

**In the console (GUI):** Applications → **Register app** → paste the manifest → **Submit** → **Approve** →
**Apply**. Apply mints the OAuth client and shows the **client secret once** (copy it now — it's stored
hashed and never shown again).

**Or by command** (same result, good for CI):

```bash
php artisan iam:manifest:apply warehouse.json --approve --by=ci-bot
```

After apply you have: an `Application` (`warehouse`), its permission catalog + roles, and an **OAuth client**
`cli_warehouse` (confidential) with `client_credentials` (or authorization_code) grants.

## Step 3 — put the credentials in the app

The app authenticates to IAM with those credentials. In the app's `.env` (the app uses one of the
[client SDKs](/guides/sdk-authentication)):

```dotenv
IAM_CLIENT_MODE=http
IAM_CLIENT_BASE_URL=https://your-iam.example.com/api/iam/v1
IAM_CLIENT_ID=cli_warehouse
IAM_CLIENT_SECRET=the-secret-you-copied      # OR IAM_CLIENT_PRIVATE_KEY=… for private_key_jwt (no secret)
IAM_CLIENT_APP=warehouse                      # default application on every decision
```

The SDK handles the OAuth token + the CSRF/idempotency plumbing for you — you don't build requests by hand.

## Step 4 — the app asks the PDP

The app never decides permissions itself; it asks IAM:

```php
if (! Iam::can($userId, 'warehouse:stock.adjust')) {
    abort(403);
}
```

Right now this returns **deny** for everyone — IAM is **default-deny**. That's correct: nobody has been
granted anything yet.

## Step 5 — create a user

**In the console (GUI):** Users → **Create user** → name, email, password → Create. (Call her *marco*.)

At this point marco can sign in, but the PDP still denies `warehouse:stock.adjust` — he has no grants.

## Step 6 — grant marco access

Give marco the app's **role** (which expands to its permissions). **In the console (GUI):** open marco in
Users (or the Roles & Grants screen) → add a grant → privilege type **role**, key **`warehouse:manager`**,
effect **permit** → save.

That single role grant expands, through the catalog, to `warehouse:stock.read` + `warehouse:stock.adjust`.

## Step 7 — marco acts, IAM allows it

marco signs in to the warehouse app and clicks "Adjust stock". The app calls `Iam::can($marco,
'warehouse:stock.adjust')` → **the PDP now allows it**, because marco holds the `manager` role that includes
that permission. He inherited the access IAM decided — the app enforced it without any local rules.

**Verify it yourself (GUI):** Decision playground → subject = marco, permission = `warehouse:stock.adjust` →
**ALLOW**, with the explanation (the role that matched). Or by command:

```bash
curl -X POST https://your-iam.example.com/api/iam/v1/decisions/check \
  -H "Content-Type: application/json" \
  -d '{"subject":{"type":"user","id":"<marco-id>"},"permission":"warehouse:stock.adjust"}'
```

## Step 8 — observe

- **Audit log** (GUI) → the `auth` stream shows marco's login; the `admin` stream shows the manifest apply
  and the grant.
- **Sessions** (GUI) → marco's live session (revoke it and he's logged out on his next request).

---

## The environment variables involved

**Server / console side** (set where IAM runs — see the full list in
[Configuration](/operations/configuration)):

| Variable | Regulates | Typical value |
| --- | --- | --- |
| `IAM_ISSUER` | the OIDC issuer identity | `https://your-iam.example.com` |
| `IAM_KMS_DRIVER` | signing-key backend | `local` (ES256 keys auto-generated) |
| `IAM_OAUTH_CLIENT_SECRET_GRACE` | zero-downtime secret rotation window (seconds) | `259200` (72h) |
| `IAM_SESSION_IDLE_TIMEOUT` / `_ABSOLUTE_TIMEOUT` | session lifetime (seconds) | `1800` / `43200` |
| `IAM_CONSOLE_2FA` / `IAM_CONSOLE_2FA_REQUIRED` | offer / force operator 2FA | `true` / `true` |

**App side** (in the consuming app's `.env`):

| Variable | Regulates | Typical value |
| --- | --- | --- |
| `IAM_CLIENT_MODE` | `local` (in-process) or `http` (remote IAM) | `http` |
| `IAM_CLIENT_BASE_URL` | the IAM Admin API base | `https://…/api/iam/v1` |
| `IAM_CLIENT_ID` | the app's OAuth client id | `cli_warehouse` |
| `IAM_CLIENT_SECRET` **or** `IAM_CLIENT_PRIVATE_KEY` | the credential (shared secret **or** private key) | one of the two |
| `IAM_CLIENT_APP` | default `application` on decisions | `warehouse` |

## Troubleshooting

- **Everything is denied.** That's default-deny — check the user actually holds the role/permission (Decision
  playground shows the reason), and that the permission key is namespaced (`warehouse:stock.adjust`).
- **"Idempotency-Key required" / CSRF errors** when scripting the Admin API directly — the console and the
  SDKs add these for you; if you call the API by hand, send an `Idempotency-Key` header on mutations.
- **`/oauth/token` 500 with "EC key generation failed"** on a local Windows box — point `IAM_OPENSSL_CONF`
  at an openssl config file. It doesn't happen on Linux hosts.
- **403 on Applications/Users after an upgrade** — re-run the role seeder so the operator's role covers the
  new permissions: `php artisan db:seed --class=Database\Seeders\IamRolesSeeder --force` (console).

## Next

- [Register an application](/guides/register-application) — the manifest lifecycle in depth.
- [private_key_jwt](/guides/private-key-jwt) — onboard with no shared secret.
- [SDK authentication modes](/guides/sdk-authentication) — how the app authenticates.
- [Application credentials & lifecycle](/guides/application-credentials) — rotation, expiry, revocation.
