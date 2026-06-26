<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\OAuth\Repositories;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use Padosoft\Iam\Domain\OAuth\Entities\ClientEntity;
use Padosoft\Iam\Domain\OAuth\Entities\ScopeEntity;
use Padosoft\Iam\Domain\OAuth\Models\OauthScope;

/**
 * Catalogo scope OAuth/OIDC (doc 13 §4): scope OIDC standard + scope dichiarati dai manifest.
 */
final class ScopeRepository implements ScopeRepositoryInterface
{
    public function getScopeEntityByIdentifier(string $identifier): ?ScopeEntityInterface
    {
        if ($identifier === '') {
            return null;
        }
        $exists = OauthScope::query()->where('identifier', $identifier)->exists();

        return $exists ? new ScopeEntity($identifier) : null;
    }

    /**
     * Restringe gli scope finali a quelli ammessi dal client: un client non può ottenere
     * scope oltre quelli che ha dichiarato (anti privilege-escalation, doc 13 §9).
     *
     * @param  ScopeEntityInterface[]  $scopes
     * @return ScopeEntityInterface[]
     */
    public function finalizeScopes(
        array $scopes,
        string $grantType,
        ClientEntityInterface $clientEntity,
        ?string $userIdentifier = null,
        ?string $authCodeId = null,
    ): array {
        $allowed = $clientEntity instanceof ClientEntity ? $clientEntity->allowedScopes : null;
        if ($allowed === null) {
            return array_values($scopes);
        }

        return array_values(array_filter(
            $scopes,
            static fn (ScopeEntityInterface $scope): bool => in_array($scope->getIdentifier(), $allowed, true),
        ));
    }
}
