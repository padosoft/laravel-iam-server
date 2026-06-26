<?php

declare(strict_types=1);

namespace Padosoft\Iam\Http\Controllers\OAuth;

use Illuminate\Http\Request;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Exception\OAuthServerException;
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

    public function __construct(private readonly AuthorizationServer $server) {}

    public function token(Request $request): Response
    {
        $psrResponse = $this->emptyPsrResponse();

        try {
            $result = $this->server->respondToAccessTokenRequest($this->toPsrRequest($request), $psrResponse);
        } catch (OAuthServerException $e) {
            $result = $e->generateHttpResponse($psrResponse);
        }

        return $this->toSymfonyResponse($result);
    }
}
