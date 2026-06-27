---
name: laravel-iam-package-workflow
description: Use when implementing ANY task in this Laravel IAM package repo. Enforces the branch/PR/test/advisory-review loop, Herd PHP 8.5 testing, the Pest+PHPStan-max+Pint gate, and LESSON.md/README upkeep. Trigger on building, coding, testing, reviewing, or releasing this package.
---

# Laravel IAM package — Workflow Skill

You are working on a **single Laravel IAM package** (one of the `padosoft/laravel-iam-*` repos, split
from the original monorepo). Follow this to the letter, across sessions.

## 1. Recover context (always, before any work)
Read in order: `LESSON.md` (traps already solved) → `RULES.md` → `CLAUDE.md` (invariants + this
package's architecture). When you spawn subagents, pass `LESSON.md` in their context.

## 2. Branch
One branch per task: `task/<name>`. PR into `main`. **Never commit to `main`.**

## 3. Definition of Done
Objective + implementation details + **test guardrails**: Pest (incl. negative tests — denial, tenant
isolation, fail-closed) + PHPStan **max** + Pint. Test locally with **PHP 8.5 via Herd** (not XAMPP).

## 4. Local gate loop (ADVISORY — never autopilot)
1. All local tests green.
2. Advisory review: `copilot -p "/review <diff of branch vs origin/main> — focus: sicurezza, fail-closed,
   invarianti IAM"` (save the diff to a temp file if large).
   ⚠️ **NEVER `copilot --autopilot --yolo`**: that mode edits/commits/pushes autonomously and has pushed
   regressed code (M1). Advisory only — you apply the fixes, keeping control.
3. Tests green AND zero advisory findings → step done. Each fix → append to `LESSON.md`.

## 5. Remote gate loop
CI green + GitHub Copilot Code Review on the PR (`gh pr edit <PR> --add-reviewer @copilot`; if it fails,
GraphQL `requestReviewsByLogin` with bot `copilot-pull-request-reviewer[bot]` — REST `reviewers[]=copilot`
is NOT equivalent) → zero comments → merge → tag/release. Never fake the loop.

## 6. Always update
`LESSON.md` on every discovery/fix. Keep README and the docmd doc-site (`docs/`) coherent with the code.

## 7. Invariants (never violate)
PDP is the only allow/deny authority (AI advisory-only) · fail-closed · no secrets/PII in logs · audit
every mutation · immutable slugs · scopes declared by manifest · UI only via Admin API · OIDC base MIT
steverhoades (no AGPL limosa-io) · OAuth = league/oauth2-server (not Passport) · root namespace
`Padosoft\Iam\`.

## 8. PHPStan max — recurring patterns (see LESSON.md for detail)
No casts on `mixed` (guard with `is_int`/`is_string`/`is_numeric`); declare `@property` on models instead
of casting in callers; never put `*/` inside a docblock; `@phpstan-impure` for methods with observable
side-effects; config read from `mixed` → rebuild as `array<string,mixed>` provably.

## 9. Inter-package dependency
This package depends on other `padosoft/laravel-iam-*` packages via Composer (Packagist). When developing
across packages locally, use a path/VCS `repositories` entry in a throwaway root project — never hardcode
paths in this package's `composer.json`.
