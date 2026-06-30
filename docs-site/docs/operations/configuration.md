---
title: Configuration
description: Every section of config/iam.php and config/iam-governance.php — authentication, tokens, OAuth, the Admin API prefix, crypto/keys, audit, observability, governance feature gates, SoD and least-privilege thresholds.
---

# Configuration

Two files are published with `php artisan vendor:publish --tag="laravel-iam-server-config"`:
`config/iam.php` and `config/iam-governance.php`. This page documents their sections.

## config/iam.php

```php
'run_migrations' => env('IAM_RUN_MIGRATIONS', true),   // load package migrations automatically
```

### authentication
Login backend wiring (Fortify / Socialite / passkeys are `suggest` dependencies — see
[Installation](/installation#choose-a-login-backend)).

### tokens
Access/id-token settings — lifetimes and claims for the JWTs the IdP issues.

### oauth

```php
'oauth' => [
    'route_prefix'   => 'oauth',        // OAuth endpoints mount here
    'register_routes'=> true,
    'rate_limit'     => 60,             // requests/min on OAuth endpoints
    'auth_code_ttl'  => 600,            // 10 minutes
    'require_pkce'   => true,           // S256 required for public clients
    'grants'         => [
        'client_credentials' => true,
        'authorization_code' => true,
        'refresh_token'      => true,
    ],
    'encryption_key' => env('IAM_OAUTH_ENCRYPTION_KEY'),  // base64 32 bytes; empty ⇒ derived from APP_KEY
],
```

### admin

```php
'admin' => [
    'route_prefix'   => 'api/iam/v1',   // the Admin API base path
    'register_routes'=> true,
    'rate_limit'     => 120,            // requests/min per client + IP
    'audience'       => env('IAM_ADMIN_AUDIENCE'),  // pin token aud (fail-closed); empty = any valid IAM token
],
```

### directory

```php
'directory' => [
    'enabled' => env('IAM_DIRECTORY_ENABLED', false),  // sync/test trigger 409 unless the -directory module is active
],
```

The server always owns directory-source **config** (CRUD); the sync/test *triggers* are delegated to
[`laravel-iam-directory`](https://doc.laravel-iam-directory.padosoft.com). If it's not active, the Admin API
returns **409** on triggers (clean degradation, not 500).

### crypto / keys
Envelope-encryption settings backing `LocalKeyProvider` / `LocalSecretCipher` — the keys that encrypt
secrets, refresh tokens and PII. The AWS KMS / Secrets Manager driver is enabled by adding `aws/aws-sdk-php`
(a `suggest` dependency).

### audit
Hash-chain and PII settings, including `ip_mode` (whether/how client IPs are stored) and export targets. See
[Tamper-evident audit](/concepts/tamper-evident-audit).

### observability
Health/readiness and the tracer (`NullTracer` / `LogTracer`). See [Observability](/operations/observability).

### governance · ai · mcp · integrations
Top-level toggles for the governance suite, the optional AI module
([`laravel-iam-ai`](https://doc.laravel-iam-ai.padosoft.com), `laravel/ai` suggest), the MCP server
(`laravel/mcp` suggest), and outbound integrations.

## config/iam-governance.php

### features
Each governance feature is gated per layer / app / role / user via `NativeFeatureScope`:

```php
'features' => [
    'access_review'     => ['default' => 'on',     'permission' => 'iam:access_review.manage'],
    'access_request'    => ['default' => 'off',    'permission' => 'iam:access_request.use'],   // privacy-by-default
    'pim'               => ['default' => 'off',     'permission' => 'iam:pim.activate'],
    'sod'               => ['default' => 'detect'],                                              // observe, don't block
    'least_privilege'   => ['default' => 'on',     'permission' => 'iam:least_privilege.view'],
    'anomaly_detection' => ['default' => 'on',     'permission' => 'iam:anomaly.view'],
],
```

### toxic_combinations
Separation-of-Duties rules — permission pairs that must not be co-held:

```php
'toxic_combinations' => [
    // ['finance:vendor.create', 'finance:payment.approve'],
],
```

### least_privilege
Deterministic recommender thresholds:

```php
'least_privilege' => [
    'unused_days'           => 90,   // grant unused N days → revoke candidate
    'dormant_days'          => 90,   // account no login N days → dormant
    'wide_role_permissions' => 50,   // role with > N permissions → too broad
],
```

## Key environment variables

| Variable | Purpose |
|---|---|
| `IAM_RUN_MIGRATIONS` | Auto-load package migrations |
| `IAM_OAUTH_ENCRYPTION_KEY` | base64 32-byte key for auth codes / refresh tokens |
| `IAM_ADMIN_AUDIENCE` | Expected `aud` of admin tokens (fail-closed) |
| `IAM_DIRECTORY_ENABLED` | Enable directory sync/test triggers |

::: callout warning "Set secrets explicitly in production" icon:key-round
Deriving the OAuth encryption key from `APP_KEY` is a dev convenience. In production set
`IAM_OAUTH_ENCRYPTION_KEY` and `IAM_ADMIN_AUDIENCE` explicitly, and back the crypto layer with a real KMS.
:::

## Next

- [Deployment](/operations/deployment) — running this in production.
- [CLI reference](/operations/cli) — the artisan commands.
- [Permissions & config reference](/reference/permissions-and-config) — the governance permission slugs.
