<?php

declare(strict_types=1);

/*
 * Configurazione di Laravel IAM Server.
 * I valori sono Draft v1 e si arricchiscono milestone per milestone (vedi laravel-iam-docs/08 §8).
 */

return [

    // Il server possiede lo schema; opt-out possibile (es. se gestisci tu le migration).
    'run_migrations' => env('IAM_RUN_MIGRATIONS', true),

    // M5 — Identity & Session (doc 10)
    'authentication' => [
        'hashing' => 'argon2id',
        'password_policy' => [
            'min_length' => 12,
            'breached_check' => true, // have-i-been-pwned k-anonymity
            'history' => 5,
        ],
        'lockout' => ['max_attempts' => 5, 'decay_seconds' => 900, 'step_up_after' => 3],
        'passkeys' => ['enabled' => true, 'rp_name' => env('IAM_RP_NAME', 'Laravel IAM')],
        'session' => [
            'idle_timeout' => (int) env('IAM_SESSION_IDLE_TIMEOUT', 1800),          // secondi, 30m
            'absolute_timeout' => (int) env('IAM_SESSION_ABSOLUTE_TIMEOUT', 43200), // secondi, 12h (mai esteso)
            'step_up_window' => (int) env('IAM_SESSION_STEPUP_WINDOW', 300),         // secondi, 5m (validità della challenge)
            // IAM-19: freschezza dell'ELEVAZIONE step-up. Un AAL2/AAL3 ottenuto via step-up "scade" dopo
            // questa finestra: un'azione requires_step_up esige uno step-up RECENTE, non uno vecchio di ore.
            // Oltre la finestra la sessione torna a valere AAL1 ai fini dell'autorizzazione step-up.
            'step_up_freshness' => (int) env('IAM_SESSION_STEPUP_FRESHNESS', 900),   // secondi, 15m
            // null/0 = nessun limite di sessioni concorrenti per subject.
            'concurrent_limit' => is_numeric(env('IAM_SESSION_CONCURRENT_LIMIT')) ? (int) env('IAM_SESSION_CONCURRENT_LIMIT') : null,
            // Retention (giorni) delle righe iam_sessions terminate/scadute — le pota `iam:prune-sessions`.
            'retention_days' => (int) env('IAM_SESSION_RETENTION_DAYS', 90),
        ],
    ],

    // M4 — OAuth/OIDC (doc 13)
    'tokens' => [
        'issuer' => env('IAM_ISSUER'), // default: app.url
        'access_ttl' => 900,
        'refresh_ttl' => 1209600,
        'signing_alg' => 'ES256', // RS256 | ES256 | EdDSA
        'introspection_for_critical' => true,
    ],

    // M4b — motore OAuth (league/oauth2-server). Le state-machine dei grant sono di league;
    // qui configuriamo TTL, grant abilitati e la chiave di cifratura per auth code/refresh.
    'oauth' => [
        'route_prefix' => 'oauth',
        'register_routes' => true,
        'rate_limit' => 60,             // richieste/minuto sugli endpoint OAuth (anti-abuse, doc 13 §9)
        'auth_code_ttl' => 600,        // 10m
        // Client-secret lifecycle (doc 13 §4.1). `ttl` = scadenza programmata del NUOVO secret (null =
        // non scade; guida gli alert quando impostato). `grace` = finestra in cui il secret PRECEDENTE
        // resta valido dopo una rotazione → rollover a zero downtime. `warn_days` = soglia "in scadenza".
        'client_secret_ttl' => env('IAM_OAUTH_CLIENT_SECRET_TTL'),                    // secondi | null
        'client_secret_grace' => (int) env('IAM_OAUTH_CLIENT_SECRET_GRACE', 259200), // 72h
        'client_secret_warn_days' => (int) env('IAM_OAUTH_CLIENT_SECRET_WARN_DAYS', 14),
        // Auto-rotation self-fetch (doc 13 §4.2): abilita POST /oauth/client-secret, con cui un client in
        // auto-rotazione ritira il nuovo secret durante il grace autenticandosi col proprio. OPT-IN
        // (secure-by-default): off → 404; accendilo solo dove usi l'auto-rotazione. Il pickup è one-time.
        'client_selffetch' => env('IAM_OAUTH_CLIENT_SELFFETCH', false),
        // private_key_jwt (RFC 7523): scarta un client_assertion la cui vita (exp − iat) supera questo (secondi).
        // Limita la finestra utile di un'assertion rubata. Il jti resta single-use fino a exp (anti-replay).
        'client_assertion_max_lifetime' => (int) env('IAM_OAUTH_CLIENT_ASSERTION_MAX_LIFETIME', 300),
        'require_pkce' => true,         // PKCE S256 obbligatorio per i client public (doc 13 §9)
        // IAM-29: scope pubblicati su /.well-known (discovery UNAUTENTICATO), oltre agli standard OIDC.
        // NON pubblicare il catalogo cross-tenant: elenca qui solo gli scope volutamente advertisable.
        'advertised_scopes' => [],
        // IAM-35: rate limit del piano OIDC (userinfo/discovery), coerente col piano OAuth.
        'oidc_rate_limit' => env('IAM_OIDC_RATE_LIMIT', '60,1'),
        'grants' => [
            'client_credentials' => true,
            'authorization_code' => true,
            'refresh_token' => true,
        ],
        // Chiave di cifratura league (base64, 32 byte) per auth code/refresh token.
        // Vuota in dev → derivata da APP_KEY (vedi IamServiceProvider::resolveOauthEncryptionKey).
        'encryption_key' => env('IAM_OAUTH_ENCRYPTION_KEY'),
    ],

    // M10 — Admin API (doc 16)
    'admin' => [
        'route_prefix' => 'api/iam/v1',
        'register_routes' => true,
        'rate_limit' => 120,            // richieste/minuto sull'Admin API (per-client+IP)
        // Audience attesa dell'access token admin: se valorizzata, un token con `aud` diverso è
        // rifiutato (fail-closed). Vuota = qualunque token IAM valido (utile in dev).
        'audience' => env('IAM_ADMIN_AUDIENCE'),
    ],

    // M17 — Directory module (doc 19 §5). Il server possiede la CONFIG delle sorgenti (CRUD sempre
    // disponibile); i trigger sync/test sono delegati al modulo padosoft/laravel-iam-directory. Se non
    // attivo, l'Admin API risponde 409 sui trigger (degradazione pulita, non 500).
    'directory' => [
        'enabled' => env('IAM_DIRECTORY_ENABLED', false),
    ],

    // M3 — Crypto/KMS (doc 11)
    'crypto' => [
        'driver' => env('IAM_KMS_DRIVER', 'local'), // local | aws | vault(v2) | azure(v2) | gcp(v2)
        'kek' => env('IAM_KEK'), // KEK base64 (32 byte). Vuoto in dev → derivata da APP_KEY.
        'openssl_config' => env('IAM_OPENSSL_CONF'), // path openssl.cnf (necessario su Windows per la keygen EC)
        'keys_path' => storage_path('keys'),
        'aws' => ['kms_key_id' => env('IAM_AWS_KMS_KEY_ID'), 'region' => env('AWS_DEFAULT_REGION')],
    ],

    // M7 — Audit (doc 12). ip_mode/ua_mode govern BOTH audit events and IdP sessions:
    //   hash (default) → salted HMAC, brute-force-safe (ip_pepper mandatory in production, fail-closed);
    //   full → the clear IP/UA, for forensics — surfaced only to sessions.read / audit.read operators.
    //          NB: `full` is only meaningful behind a correct host-side TrustProxies config, otherwise
    //          request->ip() is the proxy/load-balancer IP (e.g. on Laravel Cloud), not the real client;
    //   none → not stored. Flipping the mode is NOT retroactive: rows keep their write-time representation.
    'audit' => [
        'stream' => 'organization', // organization | global
        'ip_mode' => env('IAM_AUDIT_IP_MODE', 'hash'), // full | hash | none
        'ip_pepper' => env('IAM_AUDIT_IP_PEPPER'),
        'ua_mode' => env('IAM_AUDIT_UA_MODE', 'hash'),
        // IAM-12: chiave HMAC della hash-chain. Segreto FUORI dalle tabelle di audit → un attaccante con
        // sola-write sul DB non può ricalcolare la catena. Null = fallback su APP_KEY. In prod: chiave
        // dedicata in un KMS/secret store (ruotarla richiede un re-hash della catena esistente).
        'chain_key' => env('IAM_AUDIT_CHAIN_KEY'),
        'export' => ['format' => 'ocsf', 'sink' => env('IAM_AUDIT_SINK')], // ELK/SIEM
    ],

    // M14 — Observability / deploy base. Tracer: null (default, zero deps) | log (span/errori →
    // canale di log strutturato, spedito a OTLP/ELK da un collector). Health/ready non autenticati.
    'observability' => [
        // null (default, zero deps) | log (span → canale di log strutturato) | otlp (push nativo al
        // collector OpenTelemetry via OTLP/HTTP JSON) | stack (log + otlp insieme).
        'tracer' => env('IAM_TRACER', 'null'),
        'log_channel' => env('IAM_TRACER_CHANNEL'),  // null = canale di default
        // OTLP nativo (tracer 'otlp' o 'stack'). Endpoint = base del collector OTLP/HTTP (porta 4318);
        // il tracer aggiunge /v1/traces. gRPC (4317) non supportato: usa l'endpoint HTTP.
        'otel_endpoint' => env('IAM_OTEL_ENDPOINT'),          // es. http://otel-collector.observability.svc.cluster.local:4318
        'otel_service_name' => env('IAM_OTEL_SERVICE_NAME'),  // vuoto = app.name
        'otel_timeout' => (int) env('IAM_OTEL_TIMEOUT', 5),   // secondi (flush best-effort)
        'register_health_routes' => true,
    ],

    // M8 — Governance / IGA (doc 14)
    'governance' => [
        'features' => [
            'access_review' => ['default' => 'on', 'permission' => 'iam:access_review.manage'],
            'access_request' => ['default' => 'off', 'permission' => 'iam:access_request.use'],
            'pim' => ['default' => 'off', 'permission' => 'iam:pim.activate'],
            'sod' => ['default' => 'detect'],
        ],
        'toxic_combinations' => [
            // ['key' => 'self_approval', 'permissions' => ['iam:policies.manage', 'iam:policies.approve'], 'severity' => 'high'],
        ],
    ],

    // M11 — AI (doc 15) — advisory-only, off di default, sovrano
    'ai' => [
        'enabled' => env('IAM_AI_ENABLED', false),
        'provider' => env('IAM_AI_PROVIDER', 'regolo'), // regolo (UE) | ollama (on-prem) | azure | bedrock — MAI openai default
        'model' => env('IAM_AI_MODEL'),
        'redaction' => true,
        'store_prompts' => false,
        'store_outputs' => true,
        'max_context_events' => 500,
    ],

    // M? — MCP (doc 13/15) — v2
    'mcp' => [
        'enabled' => env('IAM_MCP_ENABLED', false),
        'require_oauth' => true,
        'dry_run_mutations_by_default' => true,
    ],

    // Integrazioni opzionali (auto-detect via class_exists)
    'integrations' => [
        'rebel' => ['enabled' => env('IAM_REBEL_ENABLED', 'auto')],
        'invitations' => ['enabled' => env('IAM_INVITATIONS_ENABLED', 'auto')],
    ],
];
