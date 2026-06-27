# Regole (sintesi) — package Laravel IAM

Dettaglio operativo: `.claude/skills/laravel-iam-package-workflow/SKILL.md`. Invarianti di sicurezza e
specifiche del package: `CLAUDE.md`. Lezioni accumulate: `LESSON.md`.

## Ambiente
- Laravel 13.x · PHP 8.3+/8.4+ (secondo `composer.json`) · **test in locale con PHP 8.5 (Herd, no XAMPP)**.
- Gate qualità: **Pest + PHPStan max (larastan) + Pint**. Test negativi obbligatori (denial, tenant
  isolation, fail-closed) dove il package li tocca.

## Processo (single-repo)
1. **Branch per task** (`task/<nome>`); PR verso `main`; mai commit diretti su `main`.
2. Ogni task: obiettivo + dettagli + **guardrail con test**.
3. **Loop locale (ADVISORY)**: test verdi → `copilot -p "/review <diff vs origin/main> — focus: sicurezza,
   fail-closed, invarianti IAM"` → zero rilievi → next. **MAI `--autopilot --yolo`** (edita/commita/pusha
   in autonomia: in M1 ha pushato codice regredito). I fix li applichi tu, mantenendo il controllo.
4. **Loop remoto**: CI verde + GitHub Copilot Code Review sulla PR → zero commenti → merge → tag/release.
5. Non fingere il loop. Se un servizio non è disponibile, registralo (PROGRESS) e prosegui sul resto.
6. Aggiorna `LESSON.md` a OGNI scoperta/fix; passa `LESSON.md` nel contesto di ogni subagent.
7. Fine task significativo ⇒ README aggiornato e doc-site coerente.

## Commit & PR
- Commit terminano con: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`
- Corpo PR termina con: `🤖 Generated with [Claude Code](https://claude.com/claude-code)`

## Invarianti di prodotto (NON violare — valgono per tutto l'ecosistema)
PDP deterministico è l'unica autorità allow/deny (**AI advisory-only**) · **fail-closed** ovunque ·
**niente segreti/OTP/PII nei log** (envelope encryption per i segreti) · **audit per ogni mutazione**
(hash-chain) · slug permessi/ruoli **immutabili** (`app_key:permission`) · scope/condition **dichiarati
dal manifest**, mai hardcoded · nessuna UI legge il DB (**solo Admin API**) · OIDC layer base **MIT
steverhoades** (vietato AGPL limosa-io) · OAuth = **league/oauth2-server** (non Passport) · namespace
radice **`Padosoft\Iam\`**.
