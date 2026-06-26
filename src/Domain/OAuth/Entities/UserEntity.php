<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\OAuth\Entities;

use League\OAuth2\Server\Entities\UserEntityInterface;

/**
 * Subject autenticato (utente IAM) legato all'authorization code / token.
 * Chi autentica l'utente è competenza del login (M5); qui si trasporta solo l'identifier.
 */
final class UserEntity implements UserEntityInterface
{
    /** @param non-empty-string $identifier */
    public function __construct(private readonly string $identifier) {}

    public function getIdentifier(): string
    {
        return $this->identifier;
    }
}
