<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\OAuth\Token;

use Padosoft\Iam\Domain\OAuth\ClientAssertionContext;
use Padosoft\Iam\Domain\OAuth\Oidc\OidcContext;

/**
 * Canale request-scoped con cui un grant deposita claim/header AGGIUNTIVI nell'access
 * token in emissione, senza aprire la costruzione dei claim a override arbitrari.
 * Nato per la delega agli AI agents (RFC 8693, modulo `padosoft/laravel-iam-agents`):
 * il grant token-exchange vi deposita `act` (l'agente che agisce per conto dell'utente),
 * `pds_dgr` (l'id della DelegationGrant, per la revoca mirata), l'`aud` richiesta
 * (audience/resource RFC 8707) e l'header `typ` dedicato dei token delegati.
 *
 * Stesso pattern di {@see OidcContext} e
 * {@see ClientAssertionContext}: singleton di richiesta,
 * resettato dal TokenController a inizio di OGNI richiesta token (Octane-safe).
 *
 * Fail-closed: le chiavi riservate NON sono impostabili — un modulo non può
 * sovrascrivere `sub`, `iss`, `scope`, `sid`, … nemmeno per errore.
 */
final class TokenIssuanceContext
{
    /**
     * Claim che questo canale NON può toccare: o li impone il signer (iss/temporali/jti),
     * o li costruisce AccessTokenClaims dalla verità del server (sub/aud/scope/sid/aal/...).
     * `act` e `pds_dgr` hanno i loro setter tipati: mai via addClaim().
     */
    private const RESERVED = [
        'iss', 'jti', 'iat', 'exp', 'nbf',
        'sub', 'aud', 'scope', 'client_id',
        'sid', 'aal', 'org', 'policy_version',
        'act', 'pds_dgr',
    ];

    /** Claim dell'attore (RFC 8693 §4.1): `{"sub":"agent:…"}`, annidato per il multi-hop. */
    private const CLAIM_ACT = 'act';

    /** Claim privato: id della DelegationGrant che autorizza l'emissione (revoca mirata). */
    private const CLAIM_DELEGATION_GRANT = 'pds_dgr';

    /** @var array<string, mixed>|null */
    private ?array $act = null;

    private ?string $delegationGrantId = null;

    /** @var list<non-empty-string> */
    private array $audience = [];

    private ?string $typ = null;

    private ?string $sessionId = null;

    /** @var array<string, mixed> */
    private array $extra = [];

    /** Parametri EXTRA di risposta ammessi (RFC 8693 §2.2: issued_token_type obbligatorio, scope se differisce). */
    private const ALLOWED_RESPONSE_PARAMS = ['issued_token_type', 'scope'];

    /** @var array<string, string> */
    private array $responseParams = [];

    /**
     * Deposita l'attore della delega (claim `act` già annidato) e la grant che la autorizza.
     *
     * @param  array<string, mixed>  $act
     */
    public function setActor(array $act, ?string $delegationGrantId = null): void
    {
        if ($act === []) {
            throw new \InvalidArgumentException('Claim `act` vuoto.');
        }
        $this->act = $act;
        $this->delegationGrantId = ($delegationGrantId !== null && $delegationGrantId !== '') ? $delegationGrantId : null;
    }

    /**
     * Override dell'audience del token (RFC 8693 `audience`/`resource`, RFC 8707):
     * il token delegato vale per la resource richiesta, non per il client emittente.
     *
     * @param  list<string>  $audience
     */
    public function setAudience(array $audience): void
    {
        $clean = [];
        foreach ($audience as $aud) {
            if ($aud !== '') {
                $clean[] = $aud;
            }
        }
        $this->audience = $clean;
    }

    /** Header `typ` del JWT in emissione (es. `delegated+jwt` per i token delegati). */
    public function setTyp(string $typ): void
    {
        if ($typ === '') {
            throw new \InvalidArgumentException('typ vuoto.');
        }
        $this->typ = $typ;
    }

    /**
     * Claim aggiuntivo generico. Le chiavi riservate sono rifiutate (fail-closed),
     * non ignorate in silenzio: un modulo che ci prova ha un bug da vedere subito.
     */
    public function addClaim(string $name, mixed $value): void
    {
        if ($name === '' || in_array($name, self::RESERVED, true)) {
            throw new \InvalidArgumentException("Claim \"{$name}\" riservato o vuoto: non impostabile via TokenIssuanceContext.");
        }
        $this->extra[$name] = $value;
    }

    /**
     * Propaga la sessione dell'utente delegante nel token emesso.
     *
     * `sid` e' RESERVED e non passa da addClaim() di proposito: un modulo qualsiasi
     * non deve poter dichiarare a quale sessione appartiene un token. Questo setter
     * esiste per il solo caso in cui la sessione va PORTATA AVANTI invariata — la
     * catena di delega multi-hop, dove ogni hop deve poter ri-verificare che la
     * sessione dell'umano sia ancora viva. Senza, il secondo hop non avrebbe modo di
     * accorgersi di un logout e la catena perderebbe il gancio di revoca proprio
     * dove diventa piu' lunga.
     */
    public function setSessionId(string $sessionId): void
    {
        if ($sessionId === '') {
            throw new \InvalidArgumentException('`sid` vuoto: non impostabile.');
        }
        $this->sessionId = $sessionId;
    }

    public function typ(): ?string
    {
        return $this->typ;
    }

    /**
     * Parametri aggiuntivi della RISPOSTA token (non del JWT): allow-list stretta
     * (`issued_token_type`, `scope` — RFC 8693 §2.2). Tutto il resto è rifiutato.
     *
     * @param  array<string, string>  $params
     */
    public function setResponseParams(array $params): void
    {
        foreach ($params as $name => $value) {
            if (!in_array($name, self::ALLOWED_RESPONSE_PARAMS, true)) {
                throw new \InvalidArgumentException("Parametro di risposta \"{$name}\" non ammesso via TokenIssuanceContext.");
            }
            if (!is_string($value)) {
                throw new \InvalidArgumentException("Parametro di risposta \"{$name}\" deve essere stringa.");
            }
        }
        $this->responseParams = $params;
    }

    /** @return array<string, string> */
    public function responseParams(): array
    {
        return $this->responseParams;
    }

    /**
     * Applica il contesto ai claim costruiti da AccessTokenClaims. Doppia guardia:
     * i setter validano all'ingresso, qui gli extra vengono comunque filtrati.
     *
     * @param  array<string, mixed>  $claims
     * @return array<string, mixed>
     */
    public function apply(array $claims): array
    {
        foreach ($this->extra as $name => $value) {
            if (!in_array($name, self::RESERVED, true)) {
                $claims[$name] = $value;
            }
        }
        if ($this->audience !== []) {
            $claims['aud'] = $this->audience;
        }
        if ($this->sessionId !== null) {
            $claims['sid'] = $this->sessionId;
        }
        if ($this->act !== null) {
            $claims[self::CLAIM_ACT] = $this->act;
            if ($this->delegationGrantId !== null) {
                $claims[self::CLAIM_DELEGATION_GRANT] = $this->delegationGrantId;
            }
        }

        return $claims;
    }

    public function reset(): void
    {
        $this->act = null;
        $this->delegationGrantId = null;
        $this->audience = [];
        $this->typ = null;
        $this->sessionId = null;
        $this->extra = [];
        $this->responseParams = [];
    }
}
