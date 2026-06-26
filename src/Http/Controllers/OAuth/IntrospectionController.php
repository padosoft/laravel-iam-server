<?php

declare(strict_types=1);

namespace Padosoft\Iam\Http\Controllers\OAuth;

use DateTimeInterface;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Padosoft\Iam\Contracts\Crypto\TokenSigner;
use Padosoft\Iam\Domain\OAuth\ClientAuthenticator;
use Padosoft\Iam\Domain\OAuth\Models\OauthAccessToken;

/**
 * Token Introspection (RFC 7662): POST /oauth/introspect. Riservato ai resource server
 * (client confidential autenticati). Fail-closed: qualsiasi dubbio ⇒ {"active": false}.
 * In v1 introspetta gli access token JWT (firma+exp+iss via TokenSigner, poi ledger/revoca).
 */
final class IntrospectionController
{
    public function __construct(
        private readonly ClientAuthenticator $clientAuth,
        private readonly TokenSigner $signer,
    ) {}

    public function introspect(Request $request): JsonResponse
    {
        $caller = $this->clientAuth->authenticate($request);
        if ($caller === null) {
            return response()->json(['error' => 'invalid_client'], 401)->header('WWW-Authenticate', 'Basic');
        }

        $token = $request->input('token');
        if (!is_string($token) || $token === '') {
            return response()->json(['active' => false]);
        }

        try {
            $claims = $this->signer->parse($token);
        } catch (\Throwable) {
            return response()->json(['active' => false]);
        }

        // Binding chiamante↔token: il caller deve essere il client del token o nella sua audience
        // (no cross-client disclosure, RFC 7662). Con aud=client_id i due check coincidono; quando
        // arriveranno i resource indicators (aud distinta) il check su aud abiliterà i resource server.
        $aud = $claims['aud'] ?? null;
        $callerIsOwner = ($claims['client_id'] ?? null) === $caller;
        $callerIsAudience = is_array($aud) && in_array($caller, $aud, true);
        if (!$callerIsOwner && !$callerIsAudience) {
            return response()->json(['active' => false]);
        }

        // Ledger: deve esistere e non essere revocato (fail-closed).
        $jti = is_string($claims['jti'] ?? null) ? $claims['jti'] : '';
        $ledger = $jti !== '' ? OauthAccessToken::query()->where('jti', $jti)->first() : null;
        if ($ledger === null || $ledger->revoked) {
            return response()->json(['active' => false]);
        }

        return response()->json([
            'active' => true,
            'scope' => is_string($claims['scope'] ?? null) ? $claims['scope'] : '',
            'client_id' => $claims['client_id'] ?? null,
            'sub' => $claims['sub'] ?? null,
            'aud' => $claims['aud'] ?? null,
            'iss' => $claims['iss'] ?? null,
            'token_type' => 'Bearer',
            'exp' => $this->timestamp($claims['exp'] ?? null),
            'iat' => $this->timestamp($claims['iat'] ?? null),
            'policy_version' => $claims['policy_version'] ?? null,
        ]);
    }

    private function timestamp(mixed $value): ?int
    {
        if ($value instanceof DateTimeInterface) {
            return $value->getTimestamp();
        }

        return is_int($value) ? $value : null;
    }
}
