---
title: "Troubleshooting"
description: "The mistakes a first-timer actually hits — missing signing keys, wrong issuer, 401/403, un-migrated DB, providers not discovered, the iam.can alias collision — each with cause → fix."
---

# Tutorial troubleshooting

The errors a newcomer hits most, with **cause → fix**. Grouped by the step where they usually surface.

## Install & migrate (steps 01–02)

::: callout warning "no such table: iam_… / SQLSTATE table not found" icon:database
**Cause:** migrations didn't run, or the app is pointed at the wrong database.
**Fix:** run `php artisan migrate`. On SQLite confirm `database/database.sqlite` exists and `.env` has
`DB_CONNECTION=sqlite`. Re-check with `php artisan tinker --execute="var_dump(Schema::hasTable('iam_grants'));"`.
:::

::: callout warning "php artisan list iam shows nothing / provider not found" icon:package
**Cause:** the service provider wasn't auto-discovered.
**Fix:** `composer dump-autoload` then `php artisan package:discover --ansi`. Confirm
`composer require padosoft/laravel-iam-server` completed without errors. The provider is
`Padosoft\Iam\IamServiceProvider`.
:::

::: callout warning "config('iam.tokens.issuer') is null" icon:settings
**Cause:** config not published, or `.env`/config edited without clearing the cache.
**Fix:** `php artisan vendor:publish --tag="laravel-iam-server-config"`, then **always**
`php artisan config:clear` after editing config or `.env`.
:::

::: callout warning "openssl_pkey_new(): Failed … (Windows / Herd) when a token is first signed" icon:key-round
**Cause:** EC key generation needs an OpenSSL config file that's missing on some Windows/Herd setups.
**Fix:** create a file whose first line is `[req]`, and set `crypto.openssl_config` in `config/iam.php` to its
path (e.g. via an env var). Then `php artisan config:clear`. Linux/macOS usually don't need this.
:::

## Decisions deny when you expect allow (steps 05–06)

::: callout warning "The PDP denies a subject you think should be allowed" icon:scale
Work through the fail-closed reasons in order:
1. **No matching grant** — the subject holds no `permit` for that `full_key` (directly or via a role). Add
   one (step 05).
2. **A deny grant exists** — deny-overrides. Any applicable `effect => 'deny'` beats a permit. Remove it.
3. **Outside the time window** — `valid_from` is in the future or `valid_until` has passed. Check the dates.
4. **Wrong scope** — the grant has an `application_key` / `organization_id` that doesn't match the check's
   `application` / `organization`.
5. **Wrong subject id** — `Iam::can($user, …)` uses the user's primary key. A grant on `user:1` only matches
   user #1. Confirm with `$user->getKey()`.
6. **Deprecated permission** — the catalog row has a `deprecated_at`; re-declare it in the manifest.
:::

::: callout warning "Every decision is false / every route 403 (client)" icon:shield
**Cause:** the client is fail-closed and something is misconfigured — a misconfiguration always *denies*,
never allows.
**Fix:** in `local` mode confirm the server lives in the same app and `IAM_CLIENT_MODE=local`,
`IAM_CLIENT_APP=warehouse` are set; `php artisan config:clear`. In `http` mode confirm
`IAM_CLIENT_BASE_URL` reaches the server and `IAM_CLIENT_TOKEN` is a valid bearer.
:::

## Route protection (step 06)

::: callout warning "Target class [iam.can] does not exist, or the Admin API middleware runs on your route" icon:route
**Cause:** the **server** owns the `iam.can` alias in a combined server+client app, so the client does not
register it.
**Fix:** reference the client's middleware **class** directly:
`Padosoft\Iam\Client\Http\Middleware\IamCan::class.':warehouse:stock.adjust'`. In a dedicated client app (no
server), the `iam.can:…` alias works as-is.
:::

::: callout warning "401 Unauthenticated on a protected route" icon:lock
**Cause:** `iam.auth` / `iam.can` require an already-authenticated user (`$request->user()`); they never log
anyone in.
**Fix:** log in first (the tutorial's `/dev-login/{id}` stand-in, or real OIDC login in step 07). Put
Laravel's `auth` guard before the IAM middleware.
:::

## OIDC / OAuth (step 07)

::: callout warning ".well-known/openid-configuration returns 404" icon:globe
**Cause:** the app isn't serving, or OIDC route registration was disabled.
**Fix:** start `php artisan serve`; check `php artisan route:list --path=well-known`. Discovery lives at the
application **root**, not under `/oauth`.
:::

::: callout warning "jwks.json has an empty keys array" icon:key
**Cause:** signing keys are created lazily; none has been generated yet.
**Fix:** this is expected before the first token is signed. Issue one token through the flow and re-fetch —
the EC P-256 verification key (with its `kid`) then appears.
:::

::: callout warning "invalid_client / redirect_uri mismatch at /oauth/token" icon:alert-triangle
**Cause:** the `client_id` or `redirect_uri` doesn't match the registered client.
**Fix:** use `client_id=cli_warehouse` and a `redirect_uri` that exactly matches the one in your step-04
manifest (`http://localhost:8000/callback`). Re-apply the manifest if you changed it.
:::

::: callout warning "The login screen never appears at /oauth/authorize" icon:log-in
**Cause:** no login backend is installed, so the IdP has nothing to render for authentication.
**Fix:** install one — `composer require laravel/fortify` (or Socialite / passkeys). They are `suggest`
dependencies, not bundled.
:::

## Admin API over HTTP (advanced)

::: callout warning "401 on /api/iam/v1/* write routes" icon:shield
**Cause:** the Admin API requires a bearer token (`iam.admin_auth`) — an IAM-issued token. The unauthenticated
routes are only `/health` and `/ready`.
**Fix:** for learning, prefer the in-process path this tutorial uses (tinker + CLI + `local` client). To call
the HTTP API, obtain a token via an OAuth flow and pin `IAM_ADMIN_AUDIENCE`. See
[Securing the Admin API](/best-practices/securing-admin-api).
:::

## Still stuck?

- Re-read the step's **"If it fails"** box — most issues are covered inline.
- Check the [Configuration](/operations/configuration) keys you touched.
- Compare against the runnable [demo app](https://github.com/padosoft/laravel-iam-demo) — it wires the whole
  ecosystem in one app and its feature tests encode the exact working API.

::: callout tip "Fail-closed is a feature, not a bug" icon:lightbulb
When in doubt, the system denies. A surprising 403 almost always means a missing/expired/mis-scoped grant or
a misconfiguration — never a silent allow. That is the safety contract working as designed.
:::
