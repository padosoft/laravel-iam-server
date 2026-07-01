---
title: "01 · Install the server"
description: "Create a Laravel 13 app, composer require laravel-iam-server (and the optional modules), run the migrations, and verify the iam_* tables and iam:* commands are really there."
---

# Step 01 · Install the server

**Goal:** end this step with a booted Laravel app that has `laravel-iam-server` installed, the full `iam_*`
schema migrated, and the `iam:*` artisan commands registered.

::: callout info "Where you are" icon:map-pin
This is step 1 of 8. Nothing here touches production — you are building a local playground on SQLite.
:::

## 1. Create a fresh Laravel app

If you already have a Laravel 13 app you want to use, skip to [step 2](#2-require-the-server). Otherwise
create one:

::: tabs
== tab "Laravel installer"
```bash
laravel new iam-lab
cd iam-lab
```
== tab "Composer"
```bash
composer create-project laravel/laravel iam-lab
cd iam-lab
```
:::

::: callout success "✅ Checkpoint" icon:check
```bash
php artisan --version
```
should print `Laravel Framework 13.x`. Laravel IAM targets **Laravel 13** on **PHP 8.3+**.
:::

## 2. Require the server

Install the control plane itself:

```bash
composer require padosoft/laravel-iam-server
```

That's the only required package. Its service provider (`Padosoft\Iam\IamServiceProvider`) is
**auto-discovered** — no `config/app.php` edits — and it pulls in
[`padosoft/laravel-iam-contracts`](https://doc.laravel-iam-contracts.padosoft.com) (the shared interfaces),
`league/oauth2-server` and `lcobucci/jwt` automatically.

### Optional modules

You will not need these for the tutorial, but this is where they go. Add only what you want — each is
independent and auto-registers:

```bash
# Consuming-app authorization (we use this in step 06 — install it now)
composer require padosoft/laravel-iam-client

# Optional extras (skip unless you want them)
composer require padosoft/laravel-iam-ai         # advisory-only AI governance (off by default)
composer require padosoft/laravel-iam-directory  # LDAP / Active Directory login + JIT provisioning
composer require padosoft/laravel-iam-bridge-spatie-permission  # migrate from spatie/laravel-permission
```

::: callout info "Server here, client in the app — but one app is fine to learn" icon:info
In production you run **`laravel-iam-server`** as a standalone IdP/PDP and install only
**`laravel-iam-client`** in each consuming app. For this tutorial we install **both in one app** (like the
[demo](https://github.com/padosoft/laravel-iam-demo)) so you see the whole loop on one machine. Install
`laravel-iam-client` now — step 06 uses it.
:::

## 3. Point the app at a database

::: tabs
== tab "SQLite (recommended)"
Create the database file and tell Laravel to use it. In `.env`:
```dotenv
DB_CONNECTION=sqlite
```
Remove (or leave blank) the `DB_HOST`, `DB_PORT`, `DB_DATABASE`, `DB_USERNAME`, `DB_PASSWORD` lines. Then
create the file:
```bash
php -r "file_exists('database/database.sqlite') || touch('database/database.sqlite');"
```
== tab "MySQL / PostgreSQL"
In `.env` set the connection to a database you have created:
```dotenv
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=iam_lab
DB_USERNAME=root
DB_PASSWORD=
```
(For PostgreSQL use `DB_CONNECTION=pgsql` and port `5432`.)
:::

Make sure the app has an application key (a fresh Laravel app already has one; run it again if unsure):

```bash
php artisan key:generate
```

## 4. Migrate — create the IAM schema

```bash
php artisan migrate
```

The server **loads its own migrations automatically** (you can toggle this with `IAM_RUN_MIGRATIONS`), so a
plain `migrate` creates the whole IAM schema: identity & sessions, the authorization catalog
(permissions / roles / grants), rotating ES256 signing keys, OAuth client & grant tables, applications &
manifests, the hash-chained audit tables, governance, ReBAC relations, groups and more — about **33 `iam_*`
tables**.

::: callout success "✅ Checkpoint — the tables exist" icon:check
Open a REPL and count them:
```bash
php artisan tinker
```
```php
>>> DB::table('sqlite_master')->where('type','table')->where('name','like','iam_%')->count();
=> 33   // a number in the low-30s
```
On MySQL/PostgreSQL use `Schema::hasTable('iam_grants')` — it should return `true`. Type `exit` to leave
tinker.
:::

## 5. Verify the commands are registered

The package registers a family of artisan commands under the `iam:` namespace. List them:

```bash
php artisan list iam
```

::: callout success "✅ Checkpoint — the iam:* commands are there" icon:check
You should see commands including:
```
iam:manifest:validate     Validate a manifest JSON without applying it
iam:manifest:apply        Apply a manifest (with --approve for gated changes)
iam:manifest:rollback     Roll back an app to its previous applied manifest
iam:audit:verify          Walk the audit hash-chain and report any break
iam:audit:checkpoint      Seal an audit stream up to now
iam:audit:export          Export audit events (SIEM)
iam:reviews:open          Open an access-review campaign
iam:least-privilege:scan  Produce least-privilege recommendations
```
The exact list depends on which optional modules you installed. See the full
[CLI reference](/operations/cli).
:::

## 6. Confirm the routes are mounted

The service provider also registers the HTTP surface. Check the Admin API is mounted:

```bash
php artisan route:list --path=api/iam/v1
```

You should see routes under `api/iam/v1` (the Admin API), plus `oauth/*` and the OIDC discovery routes.
These are all wired for you — nothing to register by hand.

::: callout warning "If it fails" icon:alert-triangle
- **`Class 'Padosoft\Iam\IamServiceProvider' not found`** → run `composer dump-autoload`, then
  `php artisan package:discover`.
- **`no such table: iam_...`** → migrations didn't run. Re-run `php artisan migrate` and check your `.env`
  DB settings. On SQLite confirm `database/database.sqlite` exists.
- **`php artisan list iam` shows nothing** → the provider isn't discovered. Run
  `php artisan package:discover --ansi` and confirm `composer require padosoft/laravel-iam-server` finished
  without errors.

More in [Troubleshooting](/tutorial/troubleshooting).
:::

## What you just did

::: steps
1. **Created** a Laravel 13 app on SQLite.
2. **Installed** `laravel-iam-server` (auto-discovered) and `laravel-iam-client`.
3. **Migrated** the full `iam_*` schema — ~33 tables — automatically.
4. **Verified** the `iam:*` commands and the `/api/iam/v1` routes exist.
:::

**Next:** configure the essentials — the token issuer, signing keys and optional modules.

**[→ Step 02 · Configure](/tutorial/02-configure)**

---

Deeper references: [Installation](/installation) · [Database schema](/reference/database-schema) ·
[CLI reference](/operations/cli)
