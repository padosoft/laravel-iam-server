<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\OAuth\Repositories;

use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use Padosoft\Iam\Domain\OAuth\Entities\AuthCodeEntity;
use Padosoft\Iam\Domain\OAuth\Models\OauthAuthCode;

/**
 * Authorization code store (doc 13 §6). Single-use: dopo lo scambio league chiama revokeAuthCode.
 */
final class AuthCodeRepository implements AuthCodeRepositoryInterface
{
    public function getNewAuthCode(): AuthCodeEntityInterface
    {
        return new AuthCodeEntity;
    }

    public function persistNewAuthCode(AuthCodeEntityInterface $authCodeEntity): void
    {
        $id = $authCodeEntity->getIdentifier();
        if (OauthAuthCode::query()->where('auth_code_id', $id)->exists()) {
            throw UniqueTokenIdentifierConstraintViolationException::create();
        }

        $scopes = array_map(
            static fn (ScopeEntityInterface $scope): string => $scope->getIdentifier(),
            $authCodeEntity->getScopes(),
        );

        OauthAuthCode::query()->create([
            'auth_code_id' => $id,
            'client_id' => $authCodeEntity->getClient()->getIdentifier(),
            'user_id' => $authCodeEntity->getUserIdentifier(),
            'scopes' => $scopes,
            'expires_at' => $authCodeEntity->getExpiryDateTime(),
        ]);
    }

    public function revokeAuthCode(string $codeId): void
    {
        OauthAuthCode::query()->where('auth_code_id', $codeId)->update(['revoked' => true]);
    }

    public function isAuthCodeRevoked(string $codeId): bool
    {
        $code = OauthAuthCode::query()->where('auth_code_id', $codeId)->first();

        // Fail-closed: code sconosciuto = revocato.
        return $code === null || $code->revoked;
    }
}
