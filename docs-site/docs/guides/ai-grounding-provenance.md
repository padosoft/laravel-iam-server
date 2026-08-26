---
title: AI grounding provenance
description: Let a permission require that the decision was not made on the strength of text an outsider wrote — using the ABAC conditions you already have.
---

# AI grounding provenance

An assistant answers from a retrieved corpus. Some of that corpus was
written by people outside your organisation: inbound email, support
tickets, scraped pages, supplier-supplied product copy. It is indexed
alongside your handbook, and at retrieval time nothing distinguishes them.

So a question worth being able to ask a permission is: *may this be
exercised on the strength of text a stranger wrote?*

For most permissions the answer is yes and nobody needs to say so. For a
few — issuing a refund, changing a payout account, deleting a customer —
the answer is no, and it should be written down where authorization
decisions are made rather than hoped for in a prompt.

## There is no new mechanism for this

The PDP's ABAC conditions are already a generic `{field: {op: value}}`
match against a free-form context. So the policy is just:

```json
{
  "grounding_provenance": { "=": "trusted_internal" }
}
```

and the PEP passes what its retrieval layer knows:

```php
$decision = $iam->check(
    subject: $user,
    permission: 'orders.refund',
    resource: $order,
    context: ['grounding_provenance' => 'untrusted_external'],
);
```

That is the whole feature. **No `provenance` column, no dedicated
operator, no second evaluator.** A narrower mechanism alongside the
general one would be a second place where "trusted" is defined, and two
definitions of trusted drift — which is the failure this design exists to
avoid, not a cost worth paying for nicer syntax.

## Why it is safe: absence is a denial

The property the whole convention rests on is that **a condition whose
field is missing from the context fails**, rather than being skipped.

A PEP that forgets to pass `grounding_provenance` — or an older caller
deployed before the field existed — is **denied**, not waved through. An
absent attribute is not a satisfied one.

This is pinned by
`tests/Feature/Authorization/ProvenanceConditionTest.php`, because a
convention is only as safe as the failure mode underneath it, and that
failure mode should not be something a future refactor can quietly
reverse.

## Suggested tier vocabulary

Any string works — the evaluator does not care. But interoperating with
the rest of the suite is worth more than expressiveness here, so use the
same three the AI packages use:

| Tier | Means |
|---|---|
| `trusted_internal` | Authored inside the organisation by someone who already had access |
| `untrusted_external` | Authored by anyone else: inbound mail, tickets, scraped pages, supplier copy |
| `machine_generated` | Produced by a model, including a summary of any of the above |

Tolerating your own summaries but not a stranger's prose:

```json
{
  "grounding_provenance": { "in": ["trusted_internal", "machine_generated"] }
}
```

`in` uses strict comparison, so tier values should be plain strings.

## Where the value actually is

The policy is the easy part. **This is only worth anything if something
labels the corpus**, and that happens at ingest, in whichever system owns
your documents — not here.

Stated plainly so nobody enables it and feels covered: a policy requiring
`trusted_internal` in an application whose PEP always passes
`trusted_internal` is a policy that denies nothing. The IAM side is the
enforcement point; the labelling is the work.

## The rest of the picture

This is the authorization-layer half of a property the AI packages enforce
at two other layers:

- **`laravel-flow`** — [provenance and taint](https://doc.laravel-flow.padosoft.com/best-practices/provenance):
  a graph that wires a model's output into a port that decides what gets
  executed is rejected at publish time, before it can run once.
- **`laravel-ai-guardrails`** — Control P: a tool call the model decided on
  while reading externally-authored grounding is refused at call time.
- **here** — a permission can require that the decision was not grounded in
  a stranger's text, with a citable decision id either way.

The three answer the same question at different distances from the action,
and none of them replaces the others.

## See also

- [Ask the PDP](/guides/ask-the-pdp)
- [Blast radius & regression](/guides/blast-radius-and-regression) — check a policy change before it ships
