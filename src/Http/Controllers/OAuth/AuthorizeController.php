<?php

declare(strict_types=1);

namespace Padosoft\Iam\Http\Controllers\OAuth;

use Illuminate\Http\Request;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Exception\OAuthServerException;
use Padosoft\Iam\Domain\OAuth\Entities\ClientEntity;
use Padosoft\Iam\Domain\OAuth\Entities\UserEntity;
use Padosoft\Iam\Domain\OAuth\Oidc\OidcContext;
use Symfony\Component\HttpFoundation\Response;

/**
 * Authorization endpoint OAuth2/OIDC (doc 13 §7): GET /oauth/authorize.
 *
 * Valida la richiesta (client, redirect_uri esatta, scope, PKCE) via league, lega il subject
 * autenticato e — per i client first-party — concede il consenso in modo implicito (doc 13 §7).
 * Chi autentica l'utente è competenza del login (M5): qui si richiede solo che sia presente.
 */
final class AuthorizeController
{
    use BridgesPsr7;

    public function __construct(
        private readonly AuthorizationServer $server,
        private readonly OidcContext $oidc,
    ) {}

    public function authorize(Request $request): Response
    {
        $this->oidc->reset();
        $psrResponse = $this->emptyPsrResponse();

        try {
            $authRequest = $this->server->validateAuthorizationRequest($this->toPsrRequest($request));

            // doc 13 §9: dove c'è PKCE è ammesso SOLO S256 (no `plain`, downgrade-proof).
            if ($authRequest->getCodeChallenge() !== null && $authRequest->getCodeChallengeMethod() !== 'S256') {
                throw OAuthServerException::invalidRequest('code_challenge_method', 'È ammesso solo S256.');
            }

            $user = $request->user();
            if ($user === null) {
                return $this->redirectToLogin();
            }
            $identifier = $user->getAuthIdentifier();
            $subject = is_scalar($identifier) ? (string) $identifier : '';
            if ($subject === '') {
                return response('Unauthenticated.', Response::HTTP_UNAUTHORIZED);
            }
            $authRequest->setUser(new UserEntity($subject));

            // OIDC: lega nonce (anti-replay) e auth_time all'auth code, per l'id_token allo scambio.
            $nonce = $request->query('nonce');
            $this->oidc->set(is_string($nonce) ? $nonce : null, new \DateTimeImmutable);

            // Consenso: first-party → implicito; third-party → consent UI esplicita (v1.x) → negato qui.
            $client = $authRequest->getClient();
            $authRequest->setAuthorizationApproved($client instanceof ClientEntity && $client->isFirstParty);

            $result = $this->server->completeAuthorizationRequest($authRequest, $psrResponse);
        } catch (OAuthServerException $e) {
            $result = $e->generateHttpResponse($psrResponse);
        }

        return $this->toSymfonyResponse($result);
    }

    private function redirectToLogin(): Response
    {
        $login = config('iam.oauth.login_route');
        if (is_string($login) && $login !== '') {
            return redirect()->guest($login);
        }

        return response('Unauthenticated.', Response::HTTP_UNAUTHORIZED);
    }
}
