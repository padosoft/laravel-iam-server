---
title: "Blast radius & policy regression"
description: "Measure what a policy change would do before it does it, and keep a corpus of probes that fails CI when authorization stops saying what you decided."
---

# Blast radius & policy regression

You are about to approve a manifest. It adds two permissions and a role. The
question every reviewer actually has is *"who can do something new after this?"* —
and until now the honest answer was **find out in production**.

Two features answer it, and they answer different questions:

| | asks | when |
|---|---|---|
| **Blast radius** | *what would change if I applied this?* | you have a change in hand |
| **Regression** | *does authorization still say what we decided?* | continuously, in CI |

Both run against the same thing: a **corpus of probes**.

## A probe

A probe is one concrete authorization question worth continuing to ask:

```http
POST /api/iam/v1/policy/probes
{
  "subject": "user:42",
  "permission": "payroll:records.read",
  "application_key": "payroll",
  "label": "the CFO reads payroll",
  "expected_allowed": true
}
```

`expected_allowed` is what turns a probe from an *observation* into an
**assertion**. Without it the probe still counts for blast radius — it says "watch
this case" — but the regression gate ignores it. That is deliberate: inventing an
expectation from current behaviour would promote every existing bug into a
requirement, which is exactly how a regression corpus stops protecting anything.

A probe carries `application_key` because the PDP filters grants by it. A probe
that omits it is asking a different question from the one the application asks.

### Two ways to fill the corpus

**By hand**, for the cases that matter — and those are the cases someone already
thought of, which are rarely the ones that break.

**By sampling real traffic**, for everything else:

```php
'simulation' => [
    'probe_sample_rate' => 0.01,   // 0 = off (the default)
    'max_probes' => 5000,
],
```

Recording is off by default, because an IAM that writes a row per authorization
check has just doubled its own write volume. When on it is sampled
**deterministically on the tuple digest** — so a recurring question is either
always in the corpus or never in it, rather than appearing and disappearing
between two runs of the same CI — deduplicated, and capped. Past the cap it stops
recording rather than growing forever: a corpus that does not fit in a human
review does not get reviewed.

Recorded probes arrive **without an expectation**. They are material to read and
promote, not assertions.

## Blast radius

```http
POST /api/iam/v1/manifests/{manifest}/blast-radius
```

```json
{
  "probes": 214,
  "counts": { "granted": 3, "revoked": 0, "step_up_added": 1, "step_up_removed": 0, "unchanged": 210 },
  "changes": [
    { "subject": "user:88", "permission": "warehouse:stock.adjust", "kind": "granted",
      "before": false, "after": true, "explanation_after": ["…"] }
  ],
  "coverage": { "probes_evaluated": 214, "note": "A blast radius is measured against these probes only…" }
}
```

The four kinds are not symmetric, and that is why they are counted separately
rather than as "N changes":

- **granted** (deny → allow) — someone gained authority. Read this first, always.
- **revoked** (allow → deny) — someone lost authority. That breaks people, not
  security: a different incident, read differently.
- **step-up added/removed** — the decision does not change but the cost to the
  user does. Counting it as "unchanged" would hide a real UX regression.
- **unchanged** — the majority, and the reason a useful report hides it by
  default (`?include_unchanged=1`).

### How it is measured

By **actually applying the manifest inside a transaction, evaluating the probes
with the real PDP, and rolling back.**

The alternative — reasoning about the change ("this grant adds permission X to
role Y, so presumably…") — is a second authorization engine, and from that moment
there are two truths that can drift: the PDP, and the model of what the PDP would
do. Here there is no second truth to keep aligned.

The price, stated plainly:

- **It never commits.** The only exit from the transaction is a rollback; there is
  no branch that commits. A test asserts the manifest is still unapplied afterwards,
  because if that ever broke, an endpoint a reviewer calls *in order not to apply
  yet* would have just applied.
- **The change really runs.** Writes, locks, triggers — all of it happens and is
  undone. What is *not* undone is anything that leaves the database: queued jobs,
  webhooks, HTTP calls. That is why the only thing simulatable here is a manifest
  apply, which is transactional by construction, and not an arbitrary mutation
  posted in a request body.
- **Inside a caller's transaction** it rolls back to a savepoint: the caller's work
  survives.

<Warning>
A blast radius of zero means **those probes** do not change — not that nothing
does. The `coverage` block says so in the payload, because "0 changes" read as
"no risk" is the way this feature would do more harm than good.
</Warning>

### Why its own permission

`iam:policies.simulate`, not `iam:policies.read`. Measuring executes the change:
it costs locks and writes even though it undoes them. That is not the same act as
reading a catalogue, so it is not the same permission.

## Regression

```bash
php artisan iam:policy:check          # exits non-zero on divergence
php artisan iam:policy:check --json   # for a pipeline
```

```
2 divergenza/e su 47 sonda/e verificata/e:
  - user:42 → payroll:records.read: atteso allow, ottenuto deny
      Nessun grant applicabile per user:42 → deny (default-deny).
```

This is where you find out that *"the CFO no longer reads payroll"* **before the
CFO does**.

It exists alongside blast radius because authority derives from things nobody
files as a policy change: a suspended user, a rewritten relation, a deprecated
role. Regression needs no change in hand — it asks whether the answer is still the
one you decided on.

A corpus with **no expectations passes, and says so out loud**:

```
Nessuna sonda con un esito atteso: questo gate non sta controllando niente.
```

A gate that passes because it has nothing to check is worse than no gate, because
it looks like one.

The same corpus is available over the API for a console:
`POST /api/iam/v1/policy/regression` — `200` when it holds, `422` with the failing
probes and the PDP's own explanation when it does not.

## Not the same as the policy wizard

`policies-wizard/preview` measures the impact of **one grant you are composing**.
This measures **a whole change** against the corpus your organisation decided to
watch. They compose: use the wizard while writing a grant, use blast radius before
approving a manifest, use regression continuously.
