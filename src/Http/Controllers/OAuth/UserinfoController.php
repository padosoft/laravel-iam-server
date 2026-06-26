<?php

declare(strict_types=1);

namespace Padosoft\Iam\Http\Controllers\OAuth;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Padosoft\Iam\Contracts\Crypto\TokenSigner;
use Padosoft\Iam\Domain\Identity\Models\User;
use Padosoft\Iam\Domain\OAuth\Models\OauthAccessToken;
use Padosoft\Iam\Domain\OAuth\Oidc\ClaimExtractor;

/**
 * UserInfo endpoint OIDC (doc 13 §7): GET /oidc/userinfo.
 *
 * Autenticato dal Bearer access token (JWT firmato da noi). Verifica firma/scadenza/issuer
 * (TokenSigner), poi controlla il ledger (revoca, fail-closed) e che lo scope includa `openid`.
 * Ritorna i claim del subject coperti dagli scope concessi.
 */
final class UserinfoController
{
    public function __construct(
        private readonly TokenSigner $signer,
        private readonly ClaimExtractor $claims,
    ) {}

    public function userinfo(Request $request): JsonResponse
    {
        $bearer = $request->bearerToken();
        if (!is_string($bearer) || $bearer === '') {
            return $this->unauthorized('invalid_token', 'Bearer token mancante.');
        }

        try {
            $claims = $this->signer->parse($bearer);
        } catch (\Throwable) {
            return $this->unauthorized('invalid_token', 'Token non valido.');
        }

        // Ledger: il token deve esistere ed essere non revocato (fail-closed).
        $jti = is_string($claims['jti'] ?? null) ? $claims['jti'] : '';
        $ledger = $jti !== '' ? OauthAccessToken::query()->where('jti', $jti)->first() : null;
        if ($ledger === null || $ledger->revoked) {
            return $this->unauthorized('invalid_token', 'Token revocato o sconosciuto.');
        }

        $scopes = $this->scopes($claims);
        if (!in_array('openid', $scopes, true)) {
            return $this->unauthorized('insufficient_scope', 'Scope openid richiesto.', 403);
        }

        $sub = is_string($claims['sub'] ?? null) ? $claims['sub'] : '';
        $user = $sub !== '' ? User::query()->find($sub) : null;
        if (!$user instanceof User) {
            return $this->unauthorized('invalid_token', 'Subject non risolvibile.');
        }

        return response()->json($this->claims->forUser($user, $scopes));
    }

    /**
     * @param  array<string, mixed>  $claims
     * @return list<string>
     */
    private function scopes(array $claims): array
    {
        $scope = is_string($claims['scope'] ?? null) ? $claims['scope'] : '';

        return array_values(array_filter(explode(' ', $scope), static fn (string $s): bool => $s !== ''));
    }

    private function unauthorized(string $error, string $description, int $status = 401): JsonResponse
    {
        return response()->json(['error' => $error, 'error_description' => $description], $status)
            ->header('WWW-Authenticate', sprintf('Bearer error="%s", error_description="%s"', $error, $description));
    }
}
