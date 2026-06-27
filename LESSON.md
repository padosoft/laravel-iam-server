# LESSON.md — lezioni dell'ecosistema Laravel IAM

> Lezioni **generali** valide per ogni package, accumulate costruendo Laravel IAM v1.0 (16 milestone,
> TDD + loop advisory). Sotto, la sezione **specifica di questo package**. Aggiorna ad ogni scoperta.

## Generali — toolchain & PHPStan max

- **Test con PHP 8.5 (Herd)**: `~/.config/herd/bin/php85/php.exe`. Su Windows, PHPStan vuole
  `--memory-limit=1G` e, prima di Pest/testbench, `attrib -R` sulla dir
  `vendor/orchestra/testbench-core/laravel/bootstrap/cache` (bug `is_writable()`). `.gitattributes eol=lf`.
- **PHPStan crash transitorio** ("Result is incomplete because of severe errors"): ri-eseguire risolve.
- **Mai cast su `mixed`**: usare guardie `is_int`/`is_string`/`is_numeric`, non `(string)`/`(int)`.
- **`@property` sui Model invece di castare nel chiamante**: una colonna castata letta da un servizio
  esterno al model fa fallire PHPStan (`property.notFound` → `Cannot cast mixed`). Dichiarare
  `@property Carbon|null` sul model; poi un `?->` su valore ora non-null diventa `nullsafe.neverNull` → `->`.
- **Mai `*/` dentro un docblock**: `decided_*/granted_id` in `/** */` CHIUDE il commento → ParseError.
- **`@phpstan-impure`** per i metodi con side-effect osservabili (mutano una proprietà pubblica e vengono
  chiamati due volte): senza, PHPStan crede il secondo valore immutato (`booleanOr.leftAlwaysFalse`).
- **Config da `mixed` → `array<string,mixed>` provabile**: `is_array($x) ? $x : []` resta `array<mixed>`;
  ricostruire con un `foreach` che casta le chiavi a stringa per soddisfare la firma.
- **larastan + generics Eloquent + closure**: `Builder<User>` non è assegnabile a `Builder<Model>`
  (invariante) e `get()` perde `TModel`. Per un paginator generico: `@param Builder<covariant Model>` +
  `callable(Model): array` con narrowing `instanceof` al call-site.

## Generali — sicurezza & processo

- **Fail-closed sempre**: default-deny, deny-overrides; un errore (transport, PDP, parsing) → deny, mai un
  allow né un 500 opaco. Vale per PDP, client, directory, AI.
- **Il loop advisory trova bug reali ad ogni slice**: TOCTOU, fail-open, takeover, info-disclosure,
  escalation. `copilot -p` (advisory), **mai** `--autopilot --yolo`. Ogni fix → qui.
- **TOCTOU sulle transizioni di stato**: leggere-poi-scrivere uno stato senza `DB::transaction` +
  `lockForUpdate` + re-check sotto lock = last-write-wins (grant orfano, doppia approvazione).
- **Snapshot vs dato vivo**: la governance congela i segnali/policy al momento giusto; l'esito non deve
  dipendere da una modifica successiva (un ruolo tolto dal catalogo non deve creare grant permanenti).
- **Tenant isolation = 404, non 403**: il cross-tenant deve essere indistinguibile da "non esiste",
  altrimenti il 403 conferma l'esistenza dell'UUID (enumerazione).
- **Deps pesanti in `suggest`, non `require`**: `aws-sdk-php`, `ldaprecord` (ext-ldap), `laravel/ai`
  rallentano/ rompono install e CI. Il core resta usabile senza; l'adapter reale è opzionale e, se non
  installabile in dev, va isolato (sottospazio + `excludePaths` PHPStan).
- **Commit message via file** se l'here-string fallisce su Windows: scrivere su file e `git commit -F`.

## Specifiche di questo package (laravel-iam-server)

- **Ogni transizione di stato sotto lock.** Approvazioni manifest (`ManifestsController::approve/apply/
  rollback`), certificazioni/revoche di access review, approvazioni di access request, revoche di sessione:
  tutte fanno read-then-write di uno stato condiviso. Senza `DB::transaction` + `lockForUpdate` + re-check,
  due richieste concorrenti producono doppia-apply o grant orfani. Il loop advisory l'ha beccato più volte.
- **La governance lavora su snapshot, non sul dato vivo.** `CampaignEngine`/`ReviewSignals` e i
  least-privilege congelano i segnali al momento giusto: l'esito di una campagna non deve cambiare perché un
  ruolo è stato tolto dal catalogo dopo l'apertura. Stesso principio per i decision-id citati in audit.
- **Cross-tenant = 404.** Negli Admin controller, una risorsa di un'altra org deve rispondere 404
  (indistinguibile da "non esiste"), mai 403 — altrimenti il 403 conferma l'esistenza dell'UUID.
- **`OpenApiSpecTest` è il guardiano del contratto HTTP.** Confronta `Router::getRoutes()` (rotte registrate
  con prefisso admin) con `resources/openapi.yaml`: ogni rotta nuova senza voce nello spec fa fallire la
  suite. Bug storico: `substr` includeva già lo slash iniziale → non anteporre `'/'` al path.
- **OAuth = `league/oauth2-server`, OIDC base MIT steverhoades.** Mai Passport, mai codice AGPL (limosa-io):
  è un vincolo di licenza dell'ecosistema. I refresh token sono cifrati (`RefreshTokenCrypto`).
- **Audit hash-chain verificabile.** Ogni mutazione passa da `AuditChainAppender`; la catena è verificabile
  via `audit/verify-chain`. PII soggetta a crypto-shredding/legal-hold (`Domain/Audit/Pii`), non cancellata
  in chiaro. `/ready` espone solo `status` (no info-disclosure su versioni/dipendenze).
