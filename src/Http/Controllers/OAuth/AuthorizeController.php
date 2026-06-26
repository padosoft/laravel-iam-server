<?php

declare(strict_types=1);

namespace Padosoft\Iam\Http\Controllers\OAuth;

use Illuminate\Http\Request;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Exception\OAuthServerException;
use Padosoft\Iam\Contracts\Identity\SessionRegistry;
use Padosoft\Iam\Domain\Identity\Models\Session;
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
        private readonly SessionRegistry $sessions,
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

            // OIDC: lega nonce e contesto sessione (sid/acr/amr/auth_time) all'auth code, per i
            // claim dell'access token (sid) e dell'id_token (acr/amr) allo scambio.
            $nonce = $request->query('nonce');
            $session = $this->resolveSession($request);
            if ($session !== null) {
                $this->oidc->set(is_string($nonce) ? $nonce : null, ($session->created_at ?? now())->toDateTimeImmutable());
                $this->oidc->setSession($session->id, $session->aal, $this->amrFor($session->aal));
            } else {
                $this->oidc->set(is_string($nonce) ? $nonce : null, new \DateTimeImmutable);
            }

            // Consenso: first-party → implicito; third-party → consent UI esplicita (v1.x) → negato qui.
            $client = $authRequest->getClient();
            $authRequest->setAuthorizationApproved($client instanceof ClientEntity && $client->isFirstParty);

            $result = $this->server->completeAuthorizationRequest($authRequest, $psrResponse);
        } catch (OAuthServerException $e) {
            $result = $e->generateHttpResponse($psrResponse);
        }

        return $this->toSymfonyResponse($result);
    }

    /** Sessione IAM corrente (sid legato alla sessione Laravel al login), se ancora attiva. */
    private function resolveSession(Request $request): ?Session
    {
        if (!$request->hasSession()) {
            return null;
        }
        $sid = $request->session()->get('iam_sid');
        if (!is_string($sid) || $sid === '' || !$this->sessions->active($sid)) {
            return null;
        }

        return Session::query()->whereKey($sid)->first();
    }

    /**
     * Metodi di autenticazione (amr) derivati dall'AAL. I metodi puntuali (pwd/otp/passkey/hwk)
     * li fornisce il login reale (Fortify/passkeys, M5.4/deploy); qui un default coerente con l'AAL.
     *
     * @return list<string>
     */
    private function amrFor(string $aal): array
    {
        return match ($aal) {
            'aal3' => ['pwd', 'hwk'],
            'aal2' => ['pwd', 'mfa'],
            default => ['pwd'],
        };
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
