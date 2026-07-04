<?php

declare(strict_types=1);

namespace Padosoft\Iam\Http\Controllers\OAuth;

use Illuminate\Http\Request;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Exception\OAuthServerException;
use Padosoft\Iam\Domain\OAuth\ClientAssertionContext;
use Padosoft\Iam\Domain\OAuth\ClientAssertionVerifier;
use Padosoft\Iam\Domain\OAuth\Oidc\OidcContext;
use Padosoft\Iam\Domain\OAuth\Repositories\RefreshTokenRepository;
use Symfony\Component\HttpFoundation\Response;

/**
 * Token endpoint OAuth2 (doc 13 §7): POST /oauth/token.
 *
 * Fa solo da bridge HTTP: converte la richiesta Laravel in PSR-7, delega a league la
 * state-machine del grant e riconverte la risposta. Gli errori OAuth (invalid_client,
 * invalid_grant, ...) sono resi conformi alla spec da league stesso.
 */
final class TokenController
{
    use BridgesPsr7;

    public function __construct(
        private readonly AuthorizationServer $server,
        private readonly RefreshTokenRepository $refreshTokens,
        private readonly OidcContext $oidc,
        private readonly ClientAssertionVerifier $assertions,
        private readonly ClientAssertionContext $assertionContext,
    ) {}

    public function token(Request $request): Response
    {
        // Chokepoint unico: azzera lo stato per-richiesta (catena di rotazione + contesto OIDC)
        // a inizio di OGNI richiesta token, così nessun residuo (es. un refresh fallito su un
        // worker Octane) può legare il token di un'altra richiesta a una catena/nonce estranei.
        $this->refreshTokens->resetPendingChain();
        $this->oidc->reset();
        $this->assertionContext->reset();

        // private_key_jwt (RFC 7523): authenticate the client by its SIGNED ASSERTION before league runs the
        // grant. On success we stash the proven client_id (ClientRepository::validateClient reads it) and hand
        // league a client_id + a non-empty placeholder secret so its confidential-client check passes — the
        // placeholder is never verified; authentication already happened here. Fail-closed on any bad assertion.
        if ($request->input('client_assertion_type') === ClientAssertionVerifier::ASSERTION_TYPE) {
            $assertion = $request->input('client_assertion');
            $clientId = is_string($assertion) ? $this->assertions->verify($assertion, $this->assertionAudiences($request)) : null;
            if ($clientId === null) {
                return $this->toSymfonyResponse(
                    OAuthServerException::invalidClient($this->toPsrRequest($request))->generateHttpResponse($this->emptyPsrResponse())
                );
            }
            $this->assertionContext->set($clientId);
            $request->merge(['client_id' => $clientId, 'client_secret' => 'private_key_jwt']);
        }

        $psrResponse = $this->emptyPsrResponse();

        try {
            $result = $this->server->respondToAccessTokenRequest($this->toPsrRequest($request), $psrResponse);
        } catch (OAuthServerException $e) {
            $result = $e->generateHttpResponse($psrResponse);
        }

        return $this->toSymfonyResponse($result);
    }

    /**
     * Acceptable `aud` values for a client assertion: this token endpoint's URL and the issuer identifier
     * (OIDC allows either). An assertion minted for another audience is rejected.
     *
     * @return list<string>
     */
    private function assertionAudiences(Request $request): array
    {
        $issuer = config('iam.tokens.issuer');

        return array_values(array_unique(array_filter([
            $request->url(),
            rtrim((string) url('/'), '/').'/oauth/token',
            is_string($issuer) && $issuer !== '' ? $issuer : null,
        ], static fn ($v): bool => is_string($v) && $v !== '')));
    }
}
