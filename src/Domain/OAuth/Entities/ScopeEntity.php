<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\OAuth\Entities;

use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\ScopeTrait;

/**
 * Scope OAuth/OIDC per league (serializza al proprio identifier).
 */
final class ScopeEntity implements ScopeEntityInterface
{
    use EntityTrait;
    use ScopeTrait;

    /** @param non-empty-string $identifier */
    public function __construct(string $identifier)
    {
        $this->identifier = $identifier;
    }
}
