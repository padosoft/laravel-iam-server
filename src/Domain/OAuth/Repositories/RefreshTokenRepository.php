<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\OAuth\Repositories;

use Illuminate\Support\Facades\DB;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use Padosoft\Iam\Domain\OAuth\Entities\RefreshTokenEntity;
use Padosoft\Iam\Domain\OAuth\Models\OauthAccessToken;
use Padosoft\Iam\Domain\OAuth\Models\OauthRefreshToken;

/**
 * Refresh token store con rotation + replay detection (doc 13 §6/§10, RFC 9700).
 *
 * Ogni refresh token appartiene a una "catena" (chain_id): l'authorization code apre una
 * nuova catena; ogni rotazione la prosegue. Se un refresh token già ruotato (revocato) viene
 * ripresentato (replay/furto), l'intera catena — e i relativi access token — viene revocata.
 *
 * `pendingChainId` è stato di richiesta: PHP-FPM crea un container per richiesta, quindi non
 * c'è bleed. Sotto Octane l'AuthorizationServer/repository non devono mantenere stato tra
 * richieste (da rivedere in M14): il valore è consumato e azzerato a ogni persist.
 */
final class RefreshTokenRepository implements RefreshTokenRepositoryInterface
{
    private ?string $pendingChainId = null;

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

        // Catena: prosecuzione di una rotazione (pendingChainId) oppure nuova catena (= se stesso).
        $chainId = $this->pendingChainId ?? $id;
        $this->pendingChainId = null; // single-use

        OauthRefreshToken::query()->create([
            'refresh_token_id' => $id,
            'chain_id' => $chainId,
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

    /** Azzera lo stato di catena pendente (chiamato a inizio di OGNI richiesta token, vedi TokenController). */
    public function resetPendingChain(): void
    {
        $this->pendingChainId = null;
    }

    /** Lega il prossimo refresh token persistito alla catena del token ruotato. */
    public function continueChain(string $oldRefreshTokenId): void
    {
        $chain = OauthRefreshToken::query()->where('refresh_token_id', $oldRefreshTokenId)->value('chain_id');
        $this->pendingChainId = is_string($chain) ? $chain : null;
    }

    /**
     * Claim atomico per la rotazione: transiziona il refresh token active→revoked sotto lock.
     * Solo UNA richiesta concorrente può riuscire; le altre vedono `revoked` e ottengono false
     * (chiude la TOCTOU tra il replay-check e la revoca di league, RFC 9700).
     */
    public function claimForRotation(string $refreshTokenId): bool
    {
        $claimed = false;
        DB::transaction(function () use ($refreshTokenId, &$claimed): void {
            $token = OauthRefreshToken::query()->where('refresh_token_id', $refreshTokenId)->lockForUpdate()->first();
            if ($token === null || $token->revoked) {
                return;
            }
            $token->revoked = true;
            $token->save();
            $claimed = true;
        });

        return $claimed;
    }

    /**
     * Replay/furto: revoca l'INTERA catena del token presentato e i relativi access token
     * (RFC 9700 §4.14.2). Atomico: snapshot + entrambe le update nella stessa transazione,
     * con lock sulle righe della catena per evitare access token sfuggiti alla revoca.
     */
    public function revokeChain(string $refreshTokenId): void
    {
        $chain = OauthRefreshToken::query()->where('refresh_token_id', $refreshTokenId)->value('chain_id');
        if (!is_string($chain) || $chain === '') {
            return;
        }

        DB::transaction(function () use ($chain): void {
            $accessJtis = OauthRefreshToken::query()->where('chain_id', $chain)->lockForUpdate()->pluck('access_token_jti')->all();
            OauthRefreshToken::query()->where('chain_id', $chain)->update(['revoked' => true]);
            OauthAccessToken::query()->whereIn('jti', $accessJtis)->update(['revoked' => true]);
        });
    }
}
