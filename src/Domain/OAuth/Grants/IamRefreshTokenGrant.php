<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\OAuth\Grants;

use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\RefreshTokenGrant;
use Padosoft\Iam\Domain\OAuth\Repositories\RefreshTokenRepository;
use Psr\Http\Message\ServerRequestInterface;

/**
 * RefreshTokenGrant con replay detection a livello di catena (doc 13 §6/§10, RFC 9700 §4.14.2):
 * un refresh token già ruotato (revocato) ripresentato ⇒ l'intera catena viene revocata.
 *
 * La rotation (revoca del vecchio refresh + emissione nuovo) è già fornita da league
 * (`revokeRefreshTokens = true`); qui aggiungiamo la propagazione alla famiglia.
 */
final class IamRefreshTokenGrant extends RefreshTokenGrant
{
    public function __construct(private readonly RefreshTokenRepository $iamRefreshTokens)
    {
        parent::__construct($iamRefreshTokens);
    }

    /**
     * @return array<string, mixed>
     */
    protected function validateOldRefreshToken(ServerRequestInterface $request, string $clientId): array
    {
        $this->iamRefreshTokens->resetPendingChain();

        $refreshTokenId = $this->peekRefreshTokenId($request);
        if ($refreshTokenId !== null && $this->iamRefreshTokens->isRefreshTokenRevoked($refreshTokenId)) {
            // Replay: refresh token già ruotato/revocato ripresentato → revoca l'intera catena.
            $this->iamRefreshTokens->revokeChain($refreshTokenId);

            throw OAuthServerException::invalidRefreshToken('Refresh token reuse detected; token chain revoked.');
        }

        $validated = parent::validateOldRefreshToken($request, $clientId);

        // Token valido: la prossima rotazione prosegue la stessa catena.
        $current = $validated['refresh_token_id'] ?? null;
        if (is_string($current) && $current !== '') {
            $this->iamRefreshTokens->continueChain($current);
        }

        return $validated;
    }

    /** Decifra il refresh token solo per leggerne l'id (rilevamento del replay). */
    private function peekRefreshTokenId(ServerRequestInterface $request): ?string
    {
        $encrypted = $this->getRequestParameter('refresh_token', $request);
        if (!is_string($encrypted) || $encrypted === '') {
            return null;
        }
        try {
            $decoded = json_decode($this->decrypt($encrypted), true, 512, JSON_THROW_ON_ERROR);
        } catch (\Throwable) {
            return null; // decrypt/parse fallito → lascia la gestione a parent (invalidRefreshToken)
        }
        $id = is_array($decoded) ? ($decoded['refresh_token_id'] ?? null) : null;

        return is_string($id) && $id !== '' ? $id : null;
    }
}
