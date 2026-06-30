---
title: Audit & compliance
description: Turning the hash-chained audit into evidence — verify the chain on a schedule, export to a SIEM, handle GDPR erasure with crypto-shredding and legal hold, and produce access-review artifacts an auditor accepts.
---

# Audit & compliance

The audit log only earns its keep when it produces *evidence*. This page is the operational discipline that
turns tamper-evidence into something you can hand an auditor.

## Verify the chain on a schedule

Tamper-evidence is only useful if you actually *check* it. Verify the chain regularly and alert on a break:

```bash
# scheduled (e.g. hourly) — fails loudly if a row was altered/deleted out of band
php artisan iam:audit:verify --stream=global
```

```php
// app/Console/Kernel.php
$schedule->command('iam:audit:verify')->hourly();
$schedule->command('iam:audit:checkpoint')->daily();   // seal streams → cheaper verification
```

A break (`AuditVerificationResult` reports the position) means out-of-band tampering — treat it as a
security incident, not a data-quality issue.

## Export to your SIEM

Stream events to your security tooling for retention and correlation:

```bash
php artisan iam:audit:export --stream=global
```

Pair with [webhooks](/guides/webhooks-and-events) for real-time delivery; the transactional outbox makes
delivery at-least-once and crash-safe. The SIEM is your long-term, queryable record; the chain is the proof
it wasn't altered.

## GDPR erasure without breaking proof

::: callout danger "Never hard-delete audit rows" icon:trash-2
Deleting rows to satisfy an erasure request breaks the hash-chain for every later event. Use
**crypto-shredding**: destroy the per-scope key so the PII is unrecoverable while the row (and the chain)
stays intact and verifiable.
:::

- **Crypto-shred** the subject's PII key on an erasure request — the event still verifies, the data is gone.
- **Legal hold** exempts records from shredding until released; apply it before shredding when litigation or
  a regulatory hold applies.
- Configure IP retention with `audit.ip_mode`.

## Produce access-review evidence

An auditor asks "who reviewed this access, when, and what did they decide?". [Access
reviews](/guides/access-reviews) answer exactly that:

::: steps
1. **Run a campaign** per scope on a schedule (quarterly is common).
2. **Attach signals** — least-privilege and SoD findings give reviewers context.
3. **Certify/revoke** every item — each decision is a dated, audited record.
4. **Close** the campaign — the frozen snapshot + decisions are your evidence.
5. **Export** the audit slice for the campaign to your evidence store.
:::

## A compliance checklist

| Control | Mechanism |
|---|---|
| Tamper-evidence | hash-chain + scheduled `iam:audit:verify` |
| Immutable retention | SIEM export + checkpoints |
| Right to erasure | crypto-shredding (not deletion) + legal hold |
| Access certification | access-review campaigns |
| Least-privilege | recommender + `iam:least-privilege:scan` |
| Separation of duties | SoD toxic combinations |
| Strong auth for sensitive ops | AAL step-up |

::: callout tip "Make verification boring" icon:check-check
The goal is that "is the audit intact?" is answered by a green scheduled job, not a manual scramble during
an audit. Wire `iam:audit:verify` into your monitoring and alert on non-zero exit.
:::

## Next

- [Tamper-evident audit](/concepts/tamper-evident-audit) — how the chain works.
- [Least-privilege & SoD](/best-practices/least-privilege-and-sod) — the signals you certify against.
- [CLI reference](/operations/cli) — the audit/review commands.
