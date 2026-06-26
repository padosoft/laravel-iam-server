<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\OAuth\Repositories;

use DateTimeImmutable;
use Illuminate\Support\Facades\DB;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use Padosoft\Iam\Domain\OAuth\Entities\RefreshTokenEntity;
use Padosoft\Iam\Domain\OAuth\Models\OauthAccessToken;
use Padosoft\Iam\Domain\OAuth\Models\OauthRefreshToken;
use Padosoft\Iam\Domain\OAuth\Models\OauthTokenChain;
use Padosoft\Iam\Domain\OAuth\Oidc\OidcContext;

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

    public function __construct(private readonly OidcContext $oidc) {}

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
        $accessJti = $refreshTokenEntity->getAccessToken()->getIdentifier();
        $expiresAt = $refreshTokenEntity->getExpiryDateTime();

        $authTime = $this->oidc->authTime();

        DB::transaction(function () use ($id, $chainId, $accessJti, $expiresAt, $authTime): void {
            // Lock della riga catena: serializza con revokeChain. Se la catena è già compromessa
            // (replay rilevato concorrentemente) il nuovo token nasce REVOCATO → niente token figlio
            // sfuggito alla revoca, qualunque sia l'ordine delle due operazioni.
            // Alla CREAZIONE della catena fissa l'auth_time originale (per gli id_token dei refresh).
            $chain = OauthTokenChain::query()->lockForUpdate()->find($chainId)
                ?? OauthTokenChain::query()->create(['chain_id' => $chainId, 'auth_time' => $authTime]);
            $compromised = $chain->compromised;

            OauthRefreshToken::query()->create([
                'refresh_token_id' => $id,
                'chain_id' => $chainId,
                'access_token_jti' => $accessJti,
                'revoked' => $compromised,
                'expires_at' => $expiresAt,
            ]);
            if ($compromised) {
                OauthAccessToken::query()->where('jti', $accessJti)->update(['revoked' => true]);
            }
        });
    }

    public function revokeRefreshToken(string $tokenId): void
    {
        OauthRefreshToken::query()->where('refresh_token_id', $tokenId)->update(['revoked' => true]);
    }

    public function isRefreshTokenRevoked(string $tokenId): bool
    {
        $token = OauthRefreshToken::query()->where('refresh_token_id', $tokenId)->first();

        // Fail-closed: refresh token sconosciuto = revocato.
        if ($token === null || $token->revoked) {
            return true;
        }

        // Anche se la riga non è (ancora) revocata, la catena può essere compromessa.
        return OauthTokenChain::query()->whereKey($token->chain_id)->where('compromised', true)->exists();
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

    /** auth_time originale della catena cui appartiene il refresh token (per l'id_token sui refresh). */
    public function chainAuthTime(string $refreshTokenId): ?DateTimeImmutable
    {
        $chainId = OauthRefreshToken::query()->where('refresh_token_id', $refreshTokenId)->value('chain_id');
        if (!is_string($chainId)) {
            return null;
        }
        $chain = OauthTokenChain::query()->whereKey($chainId)->first();

        return $chain?->auth_time?->toDateTimeImmutable();
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
     * Replay/furto: marca la catena COMPROMESSA e revoca i token esistenti + i relativi access
     * token (RFC 9700 §4.14.2). Il lock sulla riga catena serializza con persistNewRefreshToken:
     * un token figlio emesso concorrentemente o nasce revocato (catena già compromessa) o è
     * incluso nello snapshot → in nessun ordine sopravvive alla revoca.
     */
    public function revokeChain(string $refreshTokenId): void
    {
        $chain = OauthRefreshToken::query()->where('refresh_token_id', $refreshTokenId)->value('chain_id');
        if (!is_string($chain) || $chain === '') {
            return;
        }

        DB::transaction(function () use ($chain): void {
            $row = OauthTokenChain::query()->lockForUpdate()->find($chain)
                ?? OauthTokenChain::query()->create(['chain_id' => $chain]);
            $row->compromised = true;
            $row->save();

            $accessJtis = OauthRefreshToken::query()->where('chain_id', $chain)->pluck('access_token_jti')->all();
            OauthRefreshToken::query()->where('chain_id', $chain)->update(['revoked' => true]);
            OauthAccessToken::query()->whereIn('jti', $accessJtis)->update(['revoked' => true]);
        });
    }
}
