<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\OAuth\Repositories;

use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use Padosoft\Iam\Contracts\Crypto\TokenSigner;
use Padosoft\Iam\Domain\OAuth\Entities\AccessTokenEntity;
use Padosoft\Iam\Domain\OAuth\Models\OauthAccessToken;
use Padosoft\Iam\Domain\OAuth\Token\AccessTokenClaims;

/**
 * Token model ibrido (doc 13 §5): l'access token è un JWT firmato dal nostro {@see TokenSigner},
 * ma teniamo un ledger (iam_oauth_access_tokens, per jti) per introspection e revoca immediata
 * (fail-closed). league NON conosce il formato del token: chiama solo questi metodi.
 */
final class AccessTokenRepository implements AccessTokenRepositoryInterface
{
    public function __construct(
        private readonly TokenSigner $signer,
        private readonly AccessTokenClaims $claims,
    ) {}

    /**
     * @param  ScopeEntityInterface[]  $scopes
     */
    public function getNewToken(
        ClientEntityInterface $clientEntity,
        array $scopes,
        ?string $userIdentifier = null,
    ): AccessTokenEntityInterface {
        $token = new AccessTokenEntity($this->signer, $this->claims);
        $token->setClient($clientEntity);
        foreach ($scopes as $scope) {
            $token->addScope($scope);
        }
        if ($userIdentifier !== null && $userIdentifier !== '') {
            $token->setUserIdentifier($userIdentifier);
        }

        return $token;
    }

    public function persistNewAccessToken(AccessTokenEntityInterface $accessTokenEntity): void
    {
        $jti = $accessTokenEntity->getIdentifier();
        if (OauthAccessToken::query()->where('jti', $jti)->exists()) {
            // league ricatturerà l'eccezione e riproverà con un nuovo identifier.
            throw UniqueTokenIdentifierConstraintViolationException::create();
        }

        $scopes = array_map(
            static fn (ScopeEntityInterface $scope): string => $scope->getIdentifier(),
            $accessTokenEntity->getScopes(),
        );

        OauthAccessToken::query()->create([
            'jti' => $jti,
            'client_id' => $accessTokenEntity->getClient()->getIdentifier(),
            'user_id' => $accessTokenEntity->getUserIdentifier(),
            'scopes' => $scopes,
            'expires_at' => $accessTokenEntity->getExpiryDateTime(),
        ]);
    }

    public function revokeAccessToken(string $tokenId): void
    {
        OauthAccessToken::query()->where('jti', $tokenId)->update(['revoked' => true]);
    }

    public function isAccessTokenRevoked(string $tokenId): bool
    {
        $token = OauthAccessToken::query()->where('jti', $tokenId)->first();

        // Fail-closed: un token sconosciuto al ledger è trattato come revocato.
        return $token === null || $token->revoked;
    }
}
