---
title: Fail-closed design
description: Practical rules for building on the PDP without introducing privilege leaks — treat denied and thrown identically, never catch-and-allow, never cache an allow past its assumptions, and gate sensitive actions on a fresh decision.
---

# Fail-closed design

The server is fail-closed *internally*. This page is about keeping **your** code fail-closed when you build
on it. Most authorization vulnerabilities are introduced at the edge, not in the engine.

## The one rule

> Treat a **denied** decision and a **thrown** call identically: the answer is "no".

```php
try {
    $decision = $client->check('warehouse:stock.adjust', $resource, $context);
} catch (\Throwable $e) {
    // transport failure, timeout, malformed response — DENY
    return $this->deny();
}

if (! $decision->allowed) {
    return $this->deny();
}
```

::: callout danger "Never catch-and-allow" icon:shield-alert
```php
// CATASTROPHIC — a network blip becomes a privilege escalation
try { $ok = $client->check(...); } catch (\Throwable) { $ok = true; }
```
The catch branch must **deny**. This single anti-pattern is the most common authorization CVE shape.
:::

## Default to deny in your own gates

If you add a gate the PDP doesn't cover yet, default-deny:

```php
$allowed = false;          // start denied
if ($someCondition) { $allowed = true; }
return $allowed;           // unknown paths stay denied
```

Never structure it as "allow unless we found a reason to deny" — a missed branch then leaks.

## Don't cache an allow past its assumptions

A cached "allowed" is only valid while its inputs hold. Step-up assurance expires, grants are revoked, and
sessions are killed:

- Re-check sensitive actions rather than trusting a cached allow.
- Key any cache on subject + permission + resource + **policyVersion** + AAL, and keep TTLs short.
- `laravel-iam-client` caches decisions for you with sane invalidation — prefer it over rolling your own.

## Gate sensitive actions on a fresh decision

For high-impact operations (money movement, deletion, privilege grants), call the PDP **at the action**, not
at page load, and honor `requiresStepUp`:

```php
if ($decision->requiresStepUp) {
    return $this->challengeStepUp();   // AAL2, then retry
}
```

## Prefer 404 to 403 for tenant-scoped resources

When you expose data, return **404** for anything outside the caller's tenant — never 403, which confirms
existence. See [Multi-tenancy](/concepts/multi-tenancy).

## Test the denial path

The package's own suite asserts denial for malformed input, missing data, exceptions and cross-tenant
access. Mirror that in your integration tests:

- a thrown PDP call denies;
- a missing grant denies;
- a failing ABAC condition denies;
- a cross-tenant resource returns 404.

::: callout tip "Fail-closed is observable" icon:activity
A real outage in fail-closed mode looks like a spike in denials, not a silent leak. Alert on denial-rate
anomalies (the server's metrics and anomaly signals help) so you notice an outage *as* an outage.
:::

## Next

- [Deny-overrides & fail-closed](/concepts/deny-overrides-fail-closed) — the theory.
- [Securing the Admin API](/best-practices/securing-admin-api) — fail-closed at the HTTP edge.
- [Ask the PDP](/guides/ask-the-pdp) — the decision contract you gate on.
