---
title: Audit
description: Tamper-evident, hash-chained audit — append, verify, export to SIEM, and GDPR crypto-shredding / legal hold for PII.
---

# Audit

Every mutation in Laravel IAM is recorded in a **tamper-evident** audit log. The code lives in
`src/Domain/Audit/`.

## Hash-chain

Each event is hashed and linked to the previous one, forming a chain:

- `AuditHasher` — computes the per-event hash.
- `AuditChainAppender` — appends an event, linking it to the prior hash.
- `AuditChainVerifier` — walks the chain and reports any break.
- `AuditCheckpointer` — periodic checkpoints for efficient verification.

::: callout tip "Verify the chain"
```bash
curl -X POST https://iam.example.com/admin/audit/verify-chain \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```
A break means a row was altered or deleted out of band — the log is tamper-evident, not merely append-only.
:::

## Export & delivery

- **SIEM export** (`Export/`) — stream events to your security tooling.
- **Webhooks + outbox** (`Webhooks/`, `Outbox/`) — reliable, at-least-once delivery of audit/events to
  subscribers (the transactional outbox pattern survives crashes).

## PII, GDPR & legal hold

`Domain/Audit/Pii/` handles personal data in a hash-chain that you must not break:

- **Crypto-shredding** — PII is encrypted; "deletion" destroys the key, rendering the data unrecoverable
  while leaving the chain intact.
- **Legal hold** — records under hold are exempt from shredding until released.
- **`ip_mode`** — control whether/how client IPs are stored.

::: callout warning "Don't hard-delete"
Never delete audit rows to satisfy a GDPR erasure request — that breaks the chain. Use crypto-shredding so
the event still exists and verifies, but the personal data is gone.
:::

## What gets audited

Decisions (with their `decision_id`), manifest approvals/applies/rollbacks, grant changes, session
revocations, access-review certifications, access-request approvals — every state change carries an audit
entry, which is why governance can later prove who decided what.
