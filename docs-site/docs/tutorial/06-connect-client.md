---
title: "06 · Connect a client"
description: "Configure laravel-iam-client in local mode, check a decision from application code with the Iam facade, and protect a real route so Alice is allowed (200) and Bob is denied (403) — a real ALLOW/DENY at the edge."
---

# Step 06 · Connect a client

**Goal:** reach the exact decision from step 05 — but now from **application code**, not tinker. You'll use
`laravel-iam-client` to check a permission with the `Iam` facade, then protect an HTTP route so **Alice gets
in (200)** and **Bob is refused (403)**.

::: callout info "Where you are" icon:map-pin
Step 6 of 8. The PDP already decides correctly (step 05). Now a consuming app *asks* it and *enforces* the
answer.
:::

## Server vs client — and why local mode here

A consuming app never re-implements the rules — it delegates every authorization decision to the PDP through
`laravel-iam-client`. The client has two transports:

- **`local`** — the server lives in the *same* app, so the client resolves the server's `AuthorizationEngine`
  from the container and calls the PDP **in-process** (no network). This is our tutorial's single-app setup.
- **`http`** — the server is remote; the client `POST`s each query to
  `{base}/api/iam/v1/decisions/check` with a Bearer token. This is the production topology.

We use **`local`** because server and client are in one app. Switching to `http` later is one env var. See
[Choose a transport](https://doc.laravel-iam-client.padosoft.com/guides/choose-transport).

## 1. Configure the client

You installed `laravel-iam-client` in step 01. Publish its config and point it at local mode:

```bash
php artisan vendor:publish --tag=laravel-iam-client-config
```

In `.env`:

```dotenv
IAM_CLIENT_MODE=local
IAM_CLIENT_APP=warehouse
```

`IAM_CLIENT_APP=warehouse` becomes the default `application` on every query, so you don't repeat it at each
call site. Clear the config cache:

```bash
php artisan config:clear
```

## 2. Check a decision from code — the `Iam` facade

The quickest way to ask IAM from application code is the facade. Smoke-test it in tinker:

```bash
php artisan tinker
```
```php
>>> use App\Models\User;
>>> use Padosoft\Iam\Client\Facades\Iam;

>>> $alice = User::find(1);
>>> $bob   = User::find(2);

>>> Iam::can($alice, 'warehouse:stock.adjust');   // Alice holds the role granted in step 05
=> true
>>> Iam::can($bob, 'warehouse:stock.adjust');     // Bob has nothing
=> false

// Need the full decision (explanation, step-up)?
>>> Iam::check($alice, 'warehouse:stock.adjust', ['explain' => true])->granted();
=> true
```

::: callout success "✅ Checkpoint" icon:check
`Iam::can($alice, …)` is `true` and `Iam::can($bob, …)` is `false` — the same decision as step 05, now
reachable from any controller, job or Blade view. `Iam::can()` resolves the subject id from the user's
primary key, so `$alice` (id 1) matches the grant on `user:1`. Type `exit`.
:::

## 3. Protect a route — real 200 / 403

Now enforce it at the edge. Two things to know for **this single-app setup**:

::: callout warning "Alias collision: use the client middleware class here" icon:alert-triangle
The **server** already registers the `iam.can` alias (for its own Admin API), so the client does **not**
overwrite it. In this combined app, reference the client's middleware **class** directly:
`Padosoft\Iam\Client\Http\Middleware\IamCan`. In a *dedicated* client app (no server), the tidy
`iam.can:warehouse:stock.adjust` alias works out of the box.
:::

### A stand-in login (tutorial only)

`iam.can` needs an authenticated user (`$request->user()`). In step 07 that comes from real OIDC login; for
now, add a tiny **insecure, tutorial-only** login route so you can switch identity by id. In
`routes/web.php`:

```php
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use Padosoft\Iam\Client\Http\Middleware\IamCan;

// ⚠️ TUTORIAL ONLY — never ship a login-by-id route. Replace with real login (step 07).
Route::get('/dev-login/{id}', function (int $id) {
    Auth::loginUsingId($id);
    return redirect('/warehouse/adjust');
});

// The protected route: only subjects the PDP permits for warehouse:stock.adjust may enter.
Route::get('/warehouse/adjust', fn () => 'You may adjust stock. ✅')
    ->middleware(IamCan::class.':warehouse:stock.adjust');
```

### Try it

Serve the app and visit the routes in a browser (the session cookie carries the login):

```bash
php artisan serve
```

::: steps
1. **Log in as Alice, then hit the protected route**
   Visit `http://localhost:8000/dev-login/1` — it logs Alice in and redirects to `/warehouse/adjust`.
   ✅ You see **"You may adjust stock."** (HTTP 200) — the PDP permitted her.
2. **Switch to Bob**
   Visit `http://localhost:8000/dev-login/2`, which redirects to `/warehouse/adjust`.
   🚫 You get **HTTP 403** — Bob has no grant, so `iam.can` refuses him. Fail-closed, at the edge.
3. **Confirm it's the PDP deciding**
   Grant Bob the role in tinker
   (`Grant::create([... 'subject_id'=>'2', 'privilege_type'=>'role', 'privilege_key'=>'warehouse:stock_operator' ...])`),
   reload `/warehouse/adjust` as Bob → now **200**. Access follows the grants, live.
:::

::: callout success "✅ Checkpoint — end-to-end authorization" icon:party-popper
Alice reaches the route, Bob is blocked with 403, and granting Bob the role lets him in — all decided
centrally by the PDP and enforced by the client middleware. That is a working, tested IAM.
:::

## 4. Keep your existing Laravel code working

The client also registers a **Gate adapter**, so your existing `@can` and `$this->authorize()` calls consult
IAM automatically for namespaced abilities (those containing `:`):

```php
@can('warehouse:stock.adjust')
    <button>Adjust stock</button>
@endcan
```

No rewrite — the same central decision, through Laravel's own Gate. See
[Gate adapter](https://doc.laravel-iam-client.padosoft.com/guides/gate-adapter).

::: callout warning "If it fails" icon:alert-triangle
- **Every decision is `false` / every route 403** → in `local` mode the client needs the server in the same
  app (it is, here) and `IAM_CLIENT_APP=warehouse` set; run `php artisan config:clear`. Remember the client
  is **fail-closed** — a misconfiguration denies, never allows.
- **`Target class [iam.can] does not exist` or the wrong middleware runs** → you used the `iam.can` *alias*;
  in this single app use `IamCan::class` as shown above.
- **403 for Alice too** → did you delete the leftover **deny** grant from step 05? A deny overrides her
  permit.

More in [Troubleshooting](/tutorial/troubleshooting).
:::

## What you just did

::: steps
1. **Configured** `laravel-iam-client` in `local` mode against the in-app PDP.
2. **Checked** a decision from code with `Iam::can()` / `Iam::check()`.
3. **Protected a route** and saw a real **200 for Alice**, **403 for Bob**, changing live with grants.
4. **Kept** your `@can` / `authorize()` calls working via the Gate adapter.
:::

**Next:** replace the stand-in login with a real **OIDC / OAuth** login against the server's IdP.

**[→ Step 07 · OIDC / OAuth login](/tutorial/07-login-oidc)**

---

Deeper references: [laravel-iam-client docs](https://doc.laravel-iam-client.padosoft.com) ·
[Protect routes](https://doc.laravel-iam-client.padosoft.com/guides/protect-routes) ·
[Ask the PDP](/guides/ask-the-pdp)
