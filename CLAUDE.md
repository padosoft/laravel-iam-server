# CLAUDE.md — laravel-iam-server

Guida per agenti AI che lavorano in questo repo (package dell'ecosistema **Laravel IAM**). Prima di
qualsiasi lavoro leggi `LESSON.md`, `RULES.md` e questa pagina. Skill: `laravel-iam-package-workflow`.

## Cos'è questo package

Il **server** di Laravel IAM: identity, organizations, Application Registry + manifest, PDP
(RBAC+ABAC+ReBAC), OAuth (league/oauth2-server) + OIDC, audit tamper-evident (hash-chain), governance/IGA,
Admin API + panel React. È il **control plane** di Identity & Authorization dell'ecosistema.

- **Composer:** `padosoft/laravel-iam-server`
- **Namespace:** `Padosoft\Iam\`
- **Ruolo nell'ecosistema:** il **cuore**. Implementa i contratti di `laravel-iam-contracts`
  (`NativeSqlEngine` per `AuthorizationEngine`, `LocalKeyProvider`/`LocalSecretCipher`, session registry,
  `NativeFeatureScope`) ed espone l'Admin API che la console React e i `laravel-iam-client` consumano.
- **Dipende da:** `padosoft/laravel-iam-contracts`, `league/oauth2-server`, `lcobucci/jwt`,
  `symfony/psr-http-message-bridge`, `spatie/laravel-package-tools`, Laravel 13. Adapter pesanti
  (AWS KMS, LDAP, AI) sono in `suggest`, mai in `require`.

## Architettura del package

`src/` (namespace `Padosoft\Iam\…`):

- **`Domain/Identity/`** — utenti, `Session/` (session registry server-side, revocabile),
  `Assurance/` (AAL/step-up), `Federation/`, `Models/`.
- **`Domain/Organizations/`** — tenant/org (isolamento multi-tenant).
- **`Domain/Applications/`** — Application Registry + **`Manifest/`**: `ManifestValidator`,
  `ManifestDiffer`, `ManifestApplier`, `ManifestRegistry`. Le app dichiarano permessi/ruoli/scope/condition
  nel manifest; il core non hardcoda nulla.
- **`Domain/Authorization/Pdp/`** — il **PDP**: `NativeSqlEngine` (`decide(DecisionQuery): Decision`,
  RBAC+ABAC+ReBAC, **deny-overrides**, **fail-closed**), `ConditionEvaluator` (ABAC), `DecisionQuery`,
  `Decision` (con `explanation` citabile in audit). Implementa `Contracts\AuthorizationEngine`.
- **`Domain/Crypto/`** — `LocalKeyProvider` (envelope encryption), `LocalSecretCipher`
  (encrypt/decrypt/**shred** → crypto-shredding GDPR).
- **`Domain/OAuth/`** — IdP completo su `league/oauth2-server`: `Grants/`, `Entities/`, `Repositories/`,
  `ResponseTypes/`, `Token/`, `ClientAuthenticator`, `RefreshTokenCrypto`, e **`Oidc/`** (layer OIDC su base
  MIT steverhoades — **vietato AGPL limosa-io**).
- **`Domain/Audit/`** — audit **tamper-evident**: `AuditHasher` + `AuditChainAppender` /
  `AuditChainVerifier` / `AuditCheckpointer` (hash-chain), `Export/` (SIEM), `Webhooks/`, `Outbox/`,
  `Pii/` (crypto-shredding/legal hold/ip_mode), `Events/`.
- **`Domain/Governance/`** — IGA: `Reviews/` (`CampaignEngine` access review), `Requests/` (access
  request/approval), `Recommendations/` (least-privilege), `GrantUsageRecorder`, `NativeFeatureScope`
  (gating feature per layer/app/role/user).
- **`Http/Admin/`** — Admin API (controllers + `Middleware/` `iam.admin_auth`/`iam.can`/`iam.idempotency`),
  **`Http/HealthController`** + `Observability/` (`HealthCheck`, `Tracer`/`NullTracer`/`LogTracer`).
- **`routes/`** — `admin.php`, `oauth.php`, `oidc.php`, `health.php`. **`resources/openapi.yaml`** documenta
  **ogni** rotta admin (lo enforce `OpenApiSpecTest`). **`web/`** (quando presente) = console React+Vite+Tailwind.

## Invarianti (NON violare)
1. **Mai bypassare il PDP.** L'AI propone draft/spiegazioni; il PDP deterministico decide allow/deny.
2. **Fail-closed** sull'autorizzazione; mai fail-open su operazioni critiche.
3. **Niente segreti/OTP/PII nei log.** Segreti cifrati via envelope encryption.
4. **Audit per ogni mutazione** (hash-chain). Verificabile con `audit/verify-chain`.
5. **Slug permessi/ruoli immutabili** (`app_key:permission`).
6. **Scope/condition dichiarati dalle app** nel manifest, mai hardcoded nel core.
7. **Nessuna UI legge il DB**: solo Admin API.
8. **OIDC layer**: base MIT (steverhoades). **Vietato** codice AGPL (limosa-io). OAuth = league/oauth2-server (non Passport).

### Specifiche di questo package
- **TOCTOU sulle transizioni di stato**: ogni read-then-write di stato (approvazioni, rollback manifest,
  revoche, campagne) va in `DB::transaction` + `lockForUpdate` + re-check sotto lock. Last-write-wins =
  grant orfani / doppia approvazione.
- **Snapshot vs dato vivo**: la governance congela i segnali/policy al momento giusto; un ruolo tolto dal
  catalogo non deve creare grant permanenti.
- **Tenant isolation = 404, non 403**: il cross-tenant è indistinguibile da "non esiste" (no enumeration).
- **Ogni rotta admin deve stare in `openapi.yaml`**: `OpenApiSpecTest` confronta `Router::getRoutes()` con
  lo spec e fallisce se manca qualcosa.

## Convenzioni codice
- `declare(strict_types=1)`, classi `final` di default. Namespace radice **`Padosoft\Iam\`** (PSR-4).
- **PHPStan max**, **Pest**, **Pint**. Test negativi obbligatori (denial, tenant isolation, fail-closed).

## Gate (in locale, con PHP 8.5 Herd)
```bash
php vendor/bin/pint
php vendor/bin/phpstan analyse --memory-limit=1G
php vendor/bin/pest
```
> Nota: i test e il tooling QA sono stati sviluppati nel monorepo originale; vedi `LESSON.md` per il
> setup standalone. La suite di test completa di questo package è in fase di migrazione per-repo.

## Loop di lavoro
Branch per task → gate locale (test + advisory `copilot -p`, **mai `--yolo`**) → PR → CI + Copilot review
→ merge → tag. Aggiorna `LESSON.md` ad ogni fix. Dettaglio: la skill `laravel-iam-package-workflow`.
