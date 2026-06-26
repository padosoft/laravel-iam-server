<?php

declare(strict_types=1);

namespace Padosoft\Iam\Http\Controllers\OAuth;

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Padosoft\Iam\Contracts\Crypto\TokenSigner;
use Padosoft\Iam\Domain\OAuth\ClientAuthenticator;
use Padosoft\Iam\Domain\OAuth\Models\OauthAccessToken;
use Padosoft\Iam\Domain\OAuth\Models\OauthRefreshToken;
use Padosoft\Iam\Domain\OAuth\RefreshTokenCrypto;
use Padosoft\Iam\Domain\OAuth\Repositories\RefreshTokenRepository;

/**
 * Token Revocation (RFC 7009): POST /oauth/revoke. Il client autenticato può revocare i PROPRI
 * token. Access token JWT → ledger revocato; refresh token opaco → revoca dell'intera catena.
 * Per RFC 7009 la risposta è 200 anche per token sconosciuti/invalidi (no information leak).
 */
final class RevocationController
{
    public function __construct(
        private readonly ClientAuthenticator $clientAuth,
        private readonly TokenSigner $signer,
        private readonly RefreshTokenCrypto $refreshCrypto,
        private readonly RefreshTokenRepository $refreshTokens,
    ) {}

    public function revoke(Request $request): Response
    {
        $caller = $this->clientAuth->authenticate($request);
        if ($caller === null) {
            return response('', 401)->header('WWW-Authenticate', 'Basic');
        }

        $token = $request->input('token');
        if (!is_string($token) || $token === '') {
            return response('', 200);
        }

        // Access token (JWT firmato da noi).
        try {
            $claims = $this->signer->parse($token);
            $jti = is_string($claims['jti'] ?? null) ? $claims['jti'] : '';
            if ($jti !== '' && ($claims['client_id'] ?? null) === $caller) {
                OauthAccessToken::query()->where('jti', $jti)->update(['revoked' => true]);
            }

            return response('', 200);
        } catch (\Throwable) {
            // Refresh token opaco → decifra e revoca la catena (se appartiene al chiamante).
            $refreshTokenId = $this->refreshCrypto->refreshTokenId($token);
            if ($refreshTokenId !== null && $this->ownsRefreshToken($refreshTokenId, $caller)) {
                $this->refreshTokens->revokeChain($refreshTokenId);
            }

            return response('', 200);
        }
    }

    private function ownsRefreshToken(string $refreshTokenId, string $caller): bool
    {
        $refresh = OauthRefreshToken::query()->where('refresh_token_id', $refreshTokenId)->first();
        if ($refresh === null) {
            return false;
        }
        $clientId = OauthAccessToken::query()->where('jti', $refresh->access_token_jti)->value('client_id');

        return $clientId === $caller;
    }
}
