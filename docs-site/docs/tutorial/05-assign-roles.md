---
title: "05 · Assign access with Grants"
description: "Give Alice access with a Grant — a direct permit, a role grant, a time-boxed grant, an app-scoped grant — then ask the PDP in-process and watch a real ALLOW for Alice and a fail-closed DENY for Bob, plus deny-overrides."
---

# Step 05 · Assign access with Grants

**Goal:** the payoff. Assign access to Alice with the `Grant` model, then ask the **PDP** and see a real
**ALLOW**. Ask it about Bob — who has nothing — and see a fail-closed **DENY**. Then try a time-boxed grant,
an app-scoped grant, and deny-overrides.

::: callout info "Where you are" icon:map-pin
Step 5 of 8. You have users, a catalog and the `warehouse` app. Now access becomes real and provable.
:::

## The Grant model

Every assignment is a row in `iam_grants`, created through
`Padosoft\Iam\Domain\Authorization\Models\Grant`. The fields you'll use:

| Field | Meaning |
|---|---|
| `subject_type`, `subject_id` | who — e.g. `user` / `1` (Alice) |
| `privilege_type` | `permission`, `role` or `relation` |
| `privilege_key` | the `full_key` — e.g. `warehouse:stock.adjust` or `warehouse:stock_operator` |
| `effect` | `permit` or `deny` |
| `valid_from`, `valid_until` | the validity window (time-boxing) |
| `application_key` | scope to one app (`null` = global) |
| `source` | free-text provenance, e.g. `tutorial` |

## 1. Grant Alice a permission, directly

Open tinker and give Alice (`user:1`) the `warehouse:stock.adjust` permission:

```bash
php artisan tinker
```
```php
>>> use Padosoft\Iam\Domain\Authorization\Models\Grant;

>>> Grant::query()->create([
...     'subject_type'   => 'user',
...     'subject_id'     => '1',                      // Alice
...     'privilege_type' => 'permission',
...     'privilege_key'  => 'warehouse:stock.adjust',
...     'effect'         => 'permit',
...     'valid_from'     => now(),
...     'source'         => 'tutorial',
... ]);
```

## 2. Ask the PDP — the real ALLOW / DENY

The **Policy Decision Point** is the only authority on allow/deny. Resolve it from the container and call
`check()` — this is the exact API the demo app and the server's own test suite use:

```php
>>> use Padosoft\Iam\Contracts\Authorization\AuthorizationEngine;
>>> $pdp = app(AuthorizationEngine::class);

// Alice has a permit grant → ALLOW
>>> $pdp->check(['subject' => ['type' => 'user', 'id' => '1'], 'permission' => 'warehouse:stock.adjust', 'explain' => true]);
=> [ "allowed" => true, "matched" => [[ "type" => "permission", "key" => "warehouse:stock.adjust" ]], "explanation" => [...] ]

// Bob has nothing → fail-closed DENY
>>> $pdp->check(['subject' => ['type' => 'user', 'id' => '2'], 'permission' => 'warehouse:stock.adjust']);
=> [ "allowed" => false, "matched" => [], ... ]

// Alice for a permission she wasn't granted → DENY
>>> $pdp->check(['subject' => ['type' => 'user', 'id' => '1'], 'permission' => 'warehouse:stock.read']);
=> [ "allowed" => false, ... ]
```

::: callout success "✅ Checkpoint — you have a working IAM" icon:party-popper
`allowed => true` for Alice on `warehouse:stock.adjust`, `allowed => false` for Bob, and `false` for a
permission Alice doesn't hold. That is a real, deterministic, **fail-closed** authorization decision computed
by the PDP. Everything after this is making that decision reachable from an app.
:::

The `check()` input and array output:

| Query key | Meaning |
|---|---|
| `subject` | `['type' => ..., 'id' => ...]` — who is acting |
| `permission` | the `full_key` requested |
| `application` / `organization` | optional scope |
| `context` | attributes for ABAC conditions |
| `explain` | include a human-readable `explanation` |

| Result key | Meaning |
|---|---|
| `allowed` | `true` / `false` — deny-overrides, fail-closed |
| `matched` | which policies fired (`[{type, key}]`) |
| `explanation` | why (when `explain` was set) — cite it in audit |
| `requires_step_up` / `required_aal` | set when the permission needs a higher assurance level |

::: callout tip "There's also a typed API" icon:code
Internal server code can call `app(NativeSqlEngine::class)->decide(new DecisionQuery(...))` and read a typed
`Decision` object. It runs the *same* evaluation as `check()`. Details in
[Ask the PDP](/guides/ask-the-pdp).
:::

## 3. The same access via a role grant

Instead of one permission, grant Alice the **role** — the PDP expands it to every permission the role holds:

```php
// remove the direct grant first (optional), then grant the role
>>> Grant::query()->create([
...     'subject_type'   => 'user',
...     'subject_id'     => '1',
...     'privilege_type' => 'role',
...     'privilege_key'  => 'warehouse:stock_operator',
...     'effect'         => 'permit',
...     'valid_from'     => now(),
...     'source'         => 'tutorial',
... ]);

// now BOTH of the role's permissions resolve for Alice
>>> $pdp->check(['subject' => ['type' => 'user', 'id' => '1'], 'permission' => 'warehouse:stock.read'])['allowed'];
=> true
>>> $pdp->check(['subject' => ['type' => 'user', 'id' => '1'], 'permission' => 'warehouse:stock.adjust'])['allowed'];
=> true
```

One role grant, both permissions — that's RBAC. Assign the *job*, not a checklist.

## 4. Time-boxed access

A grant only counts inside its `[valid_from, valid_until]` window — the check is fail-closed outside it:

```php
// expired yesterday → DENY
>>> Grant::query()->create([
...     'subject_type' => 'user', 'subject_id' => '3',
...     'privilege_type' => 'permission', 'privilege_key' => 'warehouse:stock.read',
...     'effect' => 'permit',
...     'valid_from' => now()->subDays(2), 'valid_until' => now()->subDay(),
... ]);
>>> $pdp->check(['subject' => ['type' => 'user', 'id' => '3'], 'permission' => 'warehouse:stock.read'])['allowed'];
=> false     // the window has closed
```

Set `valid_until` to `now()->addDay()` instead and the same subject is allowed — until the window closes.
Grants can also be revoked (`$grant->revoke('user:admin')`) and support just-in-time PIM activation; see
[Access requests](/guides/access-requests).

## 5. Scope a grant to one application

A grant with an `application_key` only authorizes checks for that app — perfect isolation between apps:

```php
>>> Grant::query()->create([
...     'subject_type' => 'user', 'subject_id' => '1',
...     'application_key' => 'warehouse',
...     'privilege_type' => 'permission', 'privilege_key' => 'warehouse:stock.read',
...     'effect' => 'permit', 'valid_from' => now(),
... ]);

>>> $pdp->check(['subject' => ['type'=>'user','id'=>'1'], 'permission' => 'warehouse:stock.read', 'application' => 'warehouse'])['allowed'];
=> true
>>> $pdp->check(['subject' => ['type'=>'user','id'=>'1'], 'permission' => 'warehouse:stock.read', 'application' => 'other-app'])['allowed'];
=> false     // out of scope
```

## 6. Deny-overrides — a deny always wins

If *any* applicable grant denies, the result is deny — even alongside a permit. This is the safety rule:

```php
>>> Grant::query()->create([
...     'subject_type' => 'user', 'subject_id' => '1',
...     'privilege_type' => 'permission', 'privilege_key' => 'warehouse:stock.adjust',
...     'effect' => 'deny', 'valid_from' => now(),
... ]);
>>> $pdp->check(['subject' => ['type'=>'user','id'=>'1'], 'permission' => 'warehouse:stock.adjust', 'explain' => true])['allowed'];
=> false     // the deny beats the permit
```

::: callout warning "Clean up before the next step" icon:broom
If you added the **deny** grant above, delete it now so Alice is allowed again in step 06:
```php
>>> Grant::query()->where('subject_id','1')->where('effect','deny')->where('privilege_key','warehouse:stock.adjust')->delete();
```
Type `exit` to leave tinker.
:::

## What you just did

::: steps
1. **Granted** Alice a permission directly, and saw the PDP **ALLOW** her and **DENY** Bob.
2. **Granted** the same access via a **role**, expanding to all its permissions.
3. **Time-boxed** a grant and saw it denied outside its window.
4. **Scoped** a grant to one application.
5. **Proved deny-overrides** — a deny beats a coexisting permit, fail-closed.
:::

**Next:** stop using tinker — reach the very same decision from application code through
`laravel-iam-client`.

**[→ Step 06 · Connect a client](/tutorial/06-connect-client)**

---

Deeper references: [Ask the PDP](/guides/ask-the-pdp) ·
[Deny-overrides & fail-closed](/concepts/deny-overrides-fail-closed) · [Access requests](/guides/access-requests)
