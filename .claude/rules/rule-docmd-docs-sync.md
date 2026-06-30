# RULE — keep the docmd docs-site in sync (binding)

**This rule is mandatory and blocking.** Whenever you add or change a **user-facing feature** of
laravel-iam-server, or update the README in a substantive way, you **MUST** update the corresponding docmd
page under `docs-site/docs/**` in the **same** unit of work — following the `docmd-docs` skill.

## When it applies (you MUST update the docs-site)

- A new or changed **Admin API** route (`routes/admin.php`, `resources/openapi.yaml`) → update
  `docs-site/docs/reference/admin-api.md` and any affected guide.
- A new or changed **PDP** behavior, **manifest** schema, **OAuth/OIDC** flow, **audit**, **governance**,
  **assurance/step-up**, **CLI command** or **config key** → update the matching concept/guide/reference page.
- A new **artisan command** (`src/Console/Commands/`) → update `docs-site/docs/operations/cli.md`.
- A new **config option** (`config/iam.php`, `config/iam-governance.php`) → update
  `docs-site/docs/operations/configuration.md` and `docs-site/docs/reference/permissions-and-config.md`.
- A new **migration / table** → update `docs-site/docs/reference/database-schema.md` and
  `docs-site/docs/architecture/data-model.md`.
- A substantive **README** change (features, quick-start, ecosystem) → reflect it in the relevant page(s).

A **new page** MUST also be registered in `navigation[]` in `docmd.config.json`, or it will not appear in the
sidebar.

## When it does NOT apply (state it explicitly in the PR/changelog)

Internal refactors with no behavior change, test-only changes, tooling/CI fixes, or pure cosmetics. If you
skip a docs update, say so and why in the PR description or changelog.

## Definition of done (blocking)

1. The matching `docs-site/docs/**` page(s) reflect reality — real class/route/config names, `/api/iam/v1/`
   slash paths, `{ "data": ... }` envelope.
2. New pages are in `navigation[]`.
3. From `docs-site/`: **`npm run check` and `npm run build` are green**, and `_site/index.html` exists.

## Anti-patterns (reject in review)

- A user-facing feature shipped with no docs-site update.
- A page added but missing from `navigation[]`.
- MDX/JSX or raw HTML tags, or `::: button` (the guard fails the build).
- Documenting the old `/admin/...` path or a colon-style decisions endpoint instead of the
  `/api/iam/v1/decisions/check` slash form.
- Inventing classes/methods/config that don't exist — accuracy is non-negotiable.
