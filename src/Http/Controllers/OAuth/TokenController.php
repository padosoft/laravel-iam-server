<?php

declare(strict_types=1);

namespace Padosoft\Iam\Http\Controllers\OAuth;

use Illuminate\Http\Request;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Exception\OAuthServerException;
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
    ) {}

    public function token(Request $request): Response
    {
        // Chokepoint unico: azzera lo stato di catena pendente a inizio di OGNI richiesta token,
        // così nessun residuo (es. un refresh fallito su un worker Octane) può legare il token
        // di un'altra richiesta a una catena estranea. Vedi RefreshTokenRepository::$pendingChainId.
        $this->refreshTokens->resetPendingChain();

        $psrResponse = $this->emptyPsrResponse();

        try {
            $result = $this->server->respondToAccessTokenRequest($this->toPsrRequest($request), $psrResponse);
        } catch (OAuthServerException $e) {
            $result = $e->generateHttpResponse($psrResponse);
        }

        return $this->toSymfonyResponse($result);
    }
}
