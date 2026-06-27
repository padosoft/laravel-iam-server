# AGENTS.md — laravel-iam-server

Guida rapida per agenti (Claude Code, Copilot, ecc.) su questo repo. È il **server** dell'ecosistema
**Laravel IAM**.

## Leggi prima di lavorare
1. `LESSON.md` — trappole già risolte (TOCTOU, snapshot, tenant isolation, PHPStan max).
2. `RULES.md` — processo e invarianti di prodotto.
3. `CLAUDE.md` — invarianti + architettura reale di `src/`.
4. Skill: `.claude/skills/laravel-iam-package-workflow/SKILL.md`.

## Loop di lavoro (ADVISORY — mai autopilot)
- Branch per task (`task/<nome>`), PR verso `main`, **mai commit diretti su `main`**.
- Gate locale: test verdi (Pest, PHP 8.5 Herd) + PHPStan **max** + Pint, poi review advisory:
  ```
  copilot -p "/review <diff vs origin/main> — focus: sicurezza, fail-closed, invarianti IAM"
  ```
  ⚠️ **MAI `copilot --autopilot --yolo`**: edita/commita/pusha in autonomia e ha già pushato codice
  regredito (M1). Advisory only — i fix li applichi tu, mantenendo il controllo.
- Gate remoto: CI verde + GitHub Copilot Code Review sulla PR → zero commenti → merge → tag.

## Firma commit/PR
- Commit terminano con: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`
- Corpo PR termina con: `🤖 Generated with [Claude Code](https://claude.com/claude-code)`

## Specifico del server
- Ogni rotta admin nuova → aggiorna `resources/openapi.yaml` (lo enforce `OpenApiSpecTest`).
- Transizioni di stato → `DB::transaction` + `lockForUpdate` + re-check (vedi `LESSON.md`).
- Cross-tenant → **404**, non 403. Audit ogni mutazione (hash-chain).
