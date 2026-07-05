# Keeping IAM in sync — roles & permissions over time (every language)

Onboarding an app is step one. Then your app keeps evolving — new permissions, new roles, some retired. This
guide is the **complete story of what happens after registration**, and how each language keeps IAM in sync
without manual work.

## The one idea: the manifest is your source of truth

An application's permission catalog + roles live in a **manifest** — a small JSON document you keep **in your
repo, versioned**. To change what exists in IAM, you change the manifest and **push it**. IAM never guesses;
it applies exactly what you declare.

```
  edit/regenerate manifest  ─▶  push to IAM  ─▶  IAM diffs vs applied  ─▶  apply (or await approval)
```

- **Additive** changes (new permission/role) are low-risk → applied immediately.
- **Removing** a permission/role is a **breaking** change → it needs **approval** (a human clicks Approve in
  the console, or you pass `--approve`/an operator token).
- A removed permission/role is **never deleted** — it is **deprecated** (see below).

## Where does the manifest come from? (generation)

You can only *auto-generate* a manifest if the app has a **structured source** of roles/permissions. Exactly
one case does:

| Your app | How you get the manifest |
| --- | --- |
| **Laravel + spatie/laravel-permission** | **Auto-generated** from spatie's tables — `iam:spatie:manifest` / `iam:spatie:sync` (the [bridge](https://github.com/padosoft/laravel-iam-bridge-spatie-permission)). |
| **Laravel without spatie** | You **author** the manifest file (there is no enumerable source to scan). |
| **Node / Rust service** | You **author** the manifest file. |
| **React Native (or any pure client)** | **N/A** — a public client consumes decisions, it doesn't own a catalog. |

> Auto-generation isn't "missing" for the other cases — the manifest **is** the declaration. Writing it once
> and versioning it is the design, not a workaround.

## Validate before you push (every language)

The manifest contract is published as a **JSON Schema** so any language validates locally:

```
GET https://your-iam.example.com/.well-known/iam-manifest-schema.json
```

| Language | Validate locally |
| --- | --- |
| PHP (server host) | `php artisan iam:manifest:validate manifest.json` |
| Node | `validateManifest(manifest)` → `{ valid, errors }` |
| Rust | `validate_manifest(&manifest)` → `ManifestValidation` |
| Any (CI) | any JSON-schema tool against the published schema URL |

IAM **also** validates on submit (fail-closed) — local validation just gives you the errors before the round-trip.

## Sync: push the manifest (pick your language)

All of these submit the manifest to the Admin API (`POST /applications/{app}/manifests`); IAM diffs + applies
it. The credential must carry `iam:manifests.submit`.

**Laravel + spatie** — regenerate from the live spatie state and push in one command:

```bash
php artisan iam:spatie:sync --app=billing --dry-run     # preview the diff
php artisan iam:spatie:sync --app=billing --approve      # apply (additive) / approve+apply (breaking)
```

Schedule it for hands-off drift-sync (host `routes/console.php`):

```php
Schedule::command('iam:spatie:sync --app=billing --approve')->hourly();
```

**Laravel without spatie** — push your authored manifest file:

```bash
php artisan iam:manifest:push resources/iam/manifest.json
```

**Node**:

```ts
import { validateManifest, submitManifest } from '@padosoft/laravel-iam-node';
const { valid, errors } = validateManifest(manifest);
if (!valid) throw new Error(errors.join('; '));
await submitManifest(manifest, { baseUrl, token }); // token needs iam:manifests.submit
```

**Rust**:

```rust
let v = laravel_iam::validate_manifest(&manifest);
if !v.valid { /* handle v.errors */ }
iam.submit_manifest(None, &manifest).await?;
```

Run any of these **in CI on deploy** so IAM tracks each release automatically.

## What happens when a role or permission disappears?

**It is deprecated, not deleted — kept for history, and disabled.** When a manifest no longer declares a
permission or role that was previously applied, IAM sets its `deprecated_at`:

- The row **stays** — audit history, past grants, and "who could do what, when" remain intact and provable.
- It is **disabled** — it can no longer be granted, and it no longer satisfies a PDP decision.
- **Re-adding** the same key in a later sync **re-activates** it (clears `deprecated_at`).

This holds for **both permissions and roles**. In the **console**, deprecated entries are shown with a
**Deprecated** badge (Applications → the app's applied manifest / Roles & Grants), so an operator sees exactly
what was retired without losing the record. Nothing is silently destroyed.

> Why deprecate instead of delete? Compliance and forensics. A hard delete erases the evidence that a
> permission ever existed; deprecation keeps the timeline and makes the retirement itself auditable.

## The approval gate (additive vs breaking)

| Change | Gate | Result |
| --- | --- | --- |
| Add a permission/role | none (low-risk) | applied on submit |
| Change metadata (label, risk) | none | applied on submit |
| **Remove** a permission/role | **approval required** | submitted as *pending* → approve in the console (or `--approve` / operator token) → applied + the removed item deprecated |

## At a glance

| | Generate | Validate | Sync |
| --- | --- | --- | --- |
| Laravel + spatie | `iam:spatie:manifest` (auto) | `iam:manifest:validate` | `iam:spatie:sync` |
| Laravel (no spatie) | author file | `iam:manifest:validate` | `iam:manifest:push` |
| Node | author file | `validateManifest` | `submitManifest` |
| Rust | author file | `validate_manifest` | `submit_manifest` |
| React Native | — (consumer) | — | — |

## Next

- [End-to-end onboarding](/guides/onboarding-end-to-end) — the first registration.
- [Register an application](/guides/register-application) — the manifest lifecycle in depth.
- [SDK authentication modes](/guides/sdk-authentication) — how each SDK authenticates to push.
