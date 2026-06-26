<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\OAuth\Token;

use League\OAuth2\Server\Entities\ScopeEntityInterface;
use Padosoft\Iam\Domain\OAuth\Entities\AccessTokenEntity;
use Padosoft\Iam\Domain\OAuth\Entities\ClientEntity;
use Padosoft\Iam\Domain\Organizations\Models\Organization;

/**
 * Costruisce il claim set custom dell'access token IAM (doc 13 §5): oltre ai claim OAuth
 * standard aggiunge `policy_version` (consistency token del PDP, doc 09 §6), `org` e
 * `client_id`, così il PEP sa se la sua cache è aggiornata e per quale tenant vale il token.
 */
final class AccessTokenClaims
{
    /**
     * @return array<string, mixed>
     */
    public function build(AccessTokenEntity $token): array
    {
        $client = $token->getClient();
        $clientId = $client->getIdentifier();
        $subject = $token->getUserIdentifier() ?? $clientId;

        $scopes = array_map(
            static fn (ScopeEntityInterface $scope): string => $scope->getIdentifier(),
            $token->getScopes(),
        );

        $claims = [
            'jti' => $token->getIdentifier(),
            'sub' => $subject,
            'aud' => $clientId,           // audience-specific: il token vale per la app del client
            'client_id' => $clientId,
            'scope' => implode(' ', $scopes),
        ];

        $organizationId = $client instanceof ClientEntity ? $client->organizationId : null;
        if ($client instanceof ClientEntity && $client->organizationKey !== null) {
            $claims['org'] = $client->organizationKey;
        }
        $claims['policy_version'] = $this->policyVersion($organizationId);

        return $claims;
    }

    /** Allineato a NativeSqlEngine::policyVersion (doc 09 §6): consistency token per-org. */
    private function policyVersion(?string $organizationId): int
    {
        if ($organizationId === null) {
            return 0;
        }
        $value = Organization::query()->whereKey($organizationId)->value('policy_version');

        return is_numeric($value) ? (int) $value : 0;
    }
}
