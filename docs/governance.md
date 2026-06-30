---
title: Governance / IGA
description: Identity governance — access-review campaigns, access requests, least-privilege recommendations and SoD, gated by feature scope.
---

# Governance / IGA

Identity Governance & Administration turns raw permissions into a *governed* lifecycle. The code lives in
`src/Domain/Governance/` and is configured by `config/iam-governance.php`.

## Feature gating

Every governance feature is switchable per **layer → app → role → user** via `NativeFeatureScope` (the
server's implementation of the `FeatureScope` contract). You enable access reviews for one organization
without forcing them on everyone.

## Access reviews

`Reviews/` runs certification campaigns:

- `CampaignEngine` opens a campaign, generates items (subject × access), and closes it.
- `ReviewSignals` attaches risk signals (unused grants, anomalies) to each item so reviewers decide with
  context.
- Reviewers **certify** or **revoke** each item; every action is audited.

::: callout tip "Snapshot, not live data"
A campaign evaluates a **frozen** snapshot of grants and signals. Removing a role from the catalog after a
campaign opens must not retroactively change its outcome — and must never leave a permanent orphan grant.
:::

## Access requests

`Requests/` is the self-service + approval flow: a user browses the catalog, requests access, and an
approver approves/rejects. Approvals run under a lock (`DB::transaction` + `lockForUpdate` + re-check) so two
concurrent approvals can't double-grant.

## Least-privilege & SoD

- `Recommendations/` + `GrantUsageRecorder` surface **least-privilege** recommendations: grants that are
  held but never used.
- **Separation-of-Duties** rules flag toxic permission combinations.

## Admin API

| Area | Endpoint (prefix `/api/iam/v1`) |
| --- | --- |
| Access reviews | `GET/POST access-reviews/campaigns`, `.../open`, `.../close`, `items/{item}/certify`, `.../revoke` |
| Access requests | `GET access-requests`, `catalog`, `POST access-requests`, `.../approve`, `.../reject` |
| Recommendations | `GET recommendations/least-privilege` |

All are protected by `iam.can:iam:<permission>` and documented in `resources/openapi.yaml`.
