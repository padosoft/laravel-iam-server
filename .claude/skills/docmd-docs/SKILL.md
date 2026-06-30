---
name: docmd-docs
description: >
  Author and maintain the public documentation site for laravel-iam-server, built with docmd and living in
  docs-site/. Use this skill whenever you work inside docs-site/, add or edit a docs page, touch
  navigation/plugins in docmd.config.json, change the search/build tooling, or keep the docs in sync with a
  user-facing feature change. Covers the layout, the dev/build/check commands, the container syntax, Lucide
  icons, semantic search, branding, Cloudflare Pages deploy, the page-structure standard and the gotchas.
---

# docmd-docs — documentation site for laravel-iam-server

The public docs site is a [docmd](https://docs.docmd.io) static site in **`docs-site/`**. It is deployed by
the user on **Cloudflare Pages** (Git integration) — do **not** add a deploy CI workflow.

## Layout

```
docs-site/
  docmd.config.json          # title, url, theme, navigation (the ONLY sidebar source), plugins
  package.json               # scripts: dev / build / check
  package-lock.json          # lockfileVersion 3, cross-platform (Linux natives) — DO NOT regenerate on Windows
  .node-version              # "20"
  .gitignore                 # ignores _site/, node_modules/, .docmd-search/* except config.json
  .docmd-search/config.json  # pinned embedding model (committed; skips the interactive wizard)
  assets/favicon.svg         # teal shield (brand #0d9488)
  assets/custom.css          # brand overrides
  scripts/check-no-raw-html.mjs   # CI guard: no raw HTML / MDX / ::: button
  docs/                      # all .md pages; route mirrors the tree (docs/x/y.md → /x/y, docs/index.md → /)
  _site/                     # build output (git-ignored)
```

## Commands

```bash
cd docs-site
npm ci          # install from the committed lockfile (preferred). npm install only if npm ci fails.
npm run check   # guard: fails on raw HTML/MDX or ::: button
npm run build   # generates _site/  (must be green; _site/index.html must exist)
npm run dev     # local preview
```

## Container syntax (Markdown only — NO MDX/JSX, the guard rejects raw tags)

| Need | Syntax |
|---|---|
| Callout | `::: callout info "Title"` … `:::` (types: info, tip, warning, danger, success) |
| Tabs | `::: tabs` then `== tab "Label"` blocks, close `:::` |
| Steps | `::: steps` then numbered list `1. **Title**` with body indented **3 spaces**, close `:::` |
| Collapsible | `::: collapsible "Title"` … `:::` (prefix `open` to expand by default) |
| Cards/grids | `::: grids` › `::: grid` › `::: card "Title" icon:lucide-name` › body › `[Open →](/path)` › `:::` |
| Diagrams | fenced ```` ```mermaid ```` |
| Math | KaTeX `$…$` inline, `$$…$$` block |

Icons are **Lucide** names in kebab-case (https://lucide.dev). Never use `::: button` (use a markdown link
inside a card).

## Navigation & plugins

`navigation[]` in `docmd.config.json` is the **single source** of the sidebar — a page not listed there does
not appear. Active plugins: `search` (semantic), `git`, `seo`, `sitemap`, `mermaid`, `math`,
`llms` (`fullContext`), `analytics` (off). `seo/sitemap/llms` require the root `url`.

## Semantic search

`plugins.search.semantic: true` uses `docmd-search`: embeddings are computed at build time via ONNX; the
browser gets quantized Int8 vectors (100% client-side). The model is pinned in `.docmd-search/config.json`
(`Xenova/all-MiniLM-L6-v2`) so the build never blocks on the interactive wizard. Keep that file committed;
`.gitignore` ignores the rest of `.docmd-search/`.

## Branding & footer

Brand teal **#0d9488** (unified across the IAM ecosystem) in `assets/custom.css`. Footer credits the author
and links GitHub + Packagist: `© Lorenzo Padovani — [Padosoft](…) · [GitHub](…) · MIT`.

## Page-structure standard (deep pages)

Motivation → Theory (KaTeX where apt) → Design + a Mermaid diagram → Data model / contract → ADR (in a
`::: collapsible`, Problem→Decision→Consequences) → worked example → Gotchas (in a `::: callout warning`).
Sidebar groups: Get Started, Guides, Concepts & Theory, Architecture, Best Practices, Operations, Reference.

**Accuracy first:** document what the package actually does — real classes (`NativeSqlEngine`,
`AuditChainAppender`, `ManifestApplier`…), real routes (`/api/iam/v1/...` slash form, `{ "data": ... }`
envelope), real config keys. A wrong doc is worse than none.

## Gotchas (verified by build)

1. `docs/index.md` is mandatory (route `/`).
2. `::: button` is not a block — use a markdown link `[Open →](/path)` inside a card.
3. Steps: re-indent body **3 spaces** so nested fences/callouts stay in the item.
4. KaTeX only outside code fences.
5. Use the committed cross-platform lockfile; don't commit a lock that only resolves your OS's optional deps.

## Deploy (user does this — don't configure CI)

Cloudflare Pages: production branch `main`, root `docs-site`, build `npm run build`, output `_site`, Node via
`.node-version` (20). The site is **doc.laravel-iam-server.padosoft.com**.
