<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\OAuth;

/**
 * Request-scoped holder for the client_id proven by a verified private_key_jwt assertion.
 *
 * TokenController verifies the client_assertion and, on success, records the authenticated client_id here;
 * ClientRepository::validateClient then reads it to authorise the client WITHOUT a shared secret. Bound as
 * a `scoped` instance so it is reset per request — a stale value must never authenticate a later request.
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
