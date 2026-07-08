<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\OAuth;

/**
 * Holder for the client_id proven by a verified private_key_jwt assertion within a request.
 *
 * TokenController verifies the client_assertion and, on success, records the authenticated client_id here;
 * ClientRepository::validateClient then reads it to authorise the client WITHOUT a shared secret.
 *
 * Bound as a `singleton` (IAM-06): league's AuthorizationServer and ClientRepository capture it once, so a
 * per-request `scoped` rebind would hand TokenController a different instance than ClientRepository reads and
 * break private_key_jwt. Because the singleton survives across requests on a long-lived worker (Octane/
 * Swoole/RoadRunner), every consumer that authenticates a client MUST reset() this holder at entry so a
 * stale value can never authenticate a later request: TokenController::handle (before verifying the
 * assertion), ClientAuthenticator::authenticate (introspection/revocation) and ClientSecretController
 * (self-fetch) all reset() it. Only a verify in the SAME request may set a non-null client_id.
 */
final class ClientAssertionContext
{
    private ?string $clientId = null;

    public function set(string $clientId): void
    {
        $this->clientId = $clientId;
    }

    public function verifiedClientId(): ?string
    {
        return $this->clientId;
    }

    /** Clear at the start of every token request so a prior request's value can never authenticate a later one. */
    public function reset(): void
    {
        $this->clientId = null;
    }
}
