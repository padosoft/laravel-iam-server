<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\OAuth;

use Illuminate\Http\Request;
use Padosoft\Iam\Domain\OAuth\Repositories\ClientRepository;

/**
 * Autentica il client chiamante degli endpoint protetti (introspection RFC 7662, revocation
 * RFC 7009): credenziali via HTTP Basic o nel body (client_id/client_secret). Solo client
 * confidential con secret valido passano (ClientRepository::validateClient fail-closed).
 */
final class ClientAuthenticator
{
    public function __construct(
        private readonly ClientRepository $clients,
        private readonly ClientAssertionContext $assertions,
    ) {}

    /**
     * Ritorna il client_id autenticato, oppure null se l'autenticazione fallisce.
     * Richiede un secret non vuoto: gli endpoint protetti (introspect/revoke) sono riservati
     * ai client confidential — i client public (senza secret) sono rifiutati.
     */
    public function authenticate(Request $request): ?string
    {
        // IAM-06: questi endpoint autenticano il client SOLO via secret — non verificano mai un
        // client_assertion. Azzera qualsiasi client_id lasciato nel context condiviso da una richiesta
        // precedente (sotto Octane/Swoole il singleton sopravvive tra le richieste sul worker), così un
        // client private_key_jwt non può MAI essere autenticato qui su un valore stantìo: il ramo
        // private_key_jwt di validateClient fa fail-closed (verifiedClientId() === null !== client_id).
        $this->assertions->reset();

        [$clientId, $secret] = $this->credentials($request);
        if ($clientId === null || $secret === null || $secret === '') {
            return null;
        }

        return $this->clients->validateClient($clientId, $secret, null) ? $clientId : null;
    }

    /**
     * @return array{0: ?string, 1: ?string}
     */
    private function credentials(Request $request): array
    {
        $basicUser = $request->getUser();
        if (is_string($basicUser) && $basicUser !== '') {
            $pass = $request->getPassword();

            return [$basicUser, is_string($pass) ? $pass : null];
        }

        $clientId = $request->input('client_id');
        $secret = $request->input('client_secret');

        return [
            is_string($clientId) && $clientId !== '' ? $clientId : null,
            is_string($secret) ? $secret : null,
        ];
    }
}
