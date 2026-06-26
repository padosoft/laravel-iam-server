<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\OAuth\Repositories;

use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use Padosoft\Iam\Domain\OAuth\Entities\RefreshTokenEntity;
use Padosoft\Iam\Domain\OAuth\Models\OauthRefreshToken;

/**
 * Refresh token store (doc 13 §6). In M4b.2 fornisce persist/revoca/fail-closed;
 * la rotation con replay detection è aggiunta in M4b.3.
 */
final class RefreshTokenRepository implements RefreshTokenRepositoryInterface
{
    public function getNewRefreshToken(): RefreshTokenEntityInterface
    {
        return new RefreshTokenEntity;
    }

    public function persistNewRefreshToken(RefreshTokenEntityInterface $refreshTokenEntity): void
    {
        $id = $refreshTokenEntity->getIdentifier();
        if (OauthRefreshToken::query()->where('refresh_token_id', $id)->exists()) {
            throw UniqueTokenIdentifierConstraintViolationException::create();
        }

        OauthRefreshToken::query()->create([
            'refresh_token_id' => $id,
            'access_token_jti' => $refreshTokenEntity->getAccessToken()->getIdentifier(),
            'expires_at' => $refreshTokenEntity->getExpiryDateTime(),
        ]);
    }

    public function revokeRefreshToken(string $tokenId): void
    {
        OauthRefreshToken::query()->where('refresh_token_id', $tokenId)->update(['revoked' => true]);
    }

    public function isRefreshTokenRevoked(string $tokenId): bool
    {
        $token = OauthRefreshToken::query()->where('refresh_token_id', $tokenId)->first();

        // Fail-closed: refresh token sconosciuto = revocato.
        return $token === null || $token->revoked;
    }
}
