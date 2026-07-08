<?php

declare(strict_types=1);

namespace Padosoft\Iam\Http\Controllers\OAuth;

use Illuminate\Http\JsonResponse;

/**
 * Discovery endpoints (doc 13 §7):
 *  - GET /.well-known/openid-configuration (OIDC)
 *  - GET /.well-known/oauth-authorization-server (OAuth2, RFC 8414)
 *
 * Espone metadati e URL degli endpoint così i client si auto-configurano.
 */
final class DiscoveryController
{
    public function openidConfiguration(): JsonResponse
    {
        return response()->json($this->document())->header('Cache-Control', 'public, max-age=300');
    }

    public function oauthAuthorizationServer(): JsonResponse
    {
        return response()->json($this->document())->header('Cache-Control', 'public, max-age=300');
    }

    /**
     * @return array<string, mixed>
     */
    private function document(): array
    {
        $issuer = $this->issuer();
        $prefix = $this->prefix();

        return [
            'issuer' => $issuer,
            'authorization_endpoint' => "{$issuer}/{$prefix}/authorize",
            'token_endpoint' => "{$issuer}/{$prefix}/token",
            'userinfo_endpoint' => "{$issuer}/oidc/userinfo",
            'jwks_uri' => "{$issuer}/.well-known/jwks.json",
            'scopes_supported' => $this->scopesSupported(),
            'response_types_supported' => ['code'],
            'grant_types_supported' => $this->grantTypesSupported(),
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => ['ES256'],
            'token_endpoint_auth_methods_supported' => ['client_secret_post', 'client_secret_basic', 'private_key_jwt', 'none'],
            'token_endpoint_auth_signing_alg_values_supported' => ['ES256'],
            'code_challenge_methods_supported' => ['S256'],
        ];
    }

    private function issuer(): string
    {
        $issuer = config('iam.tokens.issuer') ?? config('app.url');

        return rtrim(is_string($issuer) && $issuer !== '' ? $issuer : 'https://iam.local', '/');
    }

    private function prefix(): string
    {
        $prefix = config('iam.oauth.route_prefix', 'oauth');

        return is_string($prefix) && $prefix !== '' ? trim($prefix, '/') : 'oauth';
    }

    /**
     * @return list<string>
     */
    private function scopesSupported(): array
    {
        // IAM-29: this endpoint is UNAUTHENTICATED. Never derive scopes_supported from an unfiltered
        // cross-tenant pluck of the whole catalog — that discloses every tenant's permission slugs to the
        // public. Advertise only the standard OIDC scopes plus an explicitly curated allowlist
        // (iam.oauth.advertised_scopes). scopes_supported is optional metadata, so omitting the catalog is safe.
        $standard = ['openid', 'profile', 'email'];
        $advertised = config('iam.oauth.advertised_scopes', []);
        $advertised = is_array($advertised) ? array_values(array_filter($advertised, 'is_string')) : [];

        return array_values(array_unique([...$standard, ...$advertised]));
    }

    /**
     * @return list<string>
     */
    private function grantTypesSupported(): array
    {
        $grants = config('iam.oauth.grants', []);
        $enabled = [];
        if (is_array($grants)) {
            foreach ($grants as $name => $on) {
                if (is_string($name) && (bool) $on) {
                    $enabled[] = $name;
                }
            }
        }

        return $enabled !== [] ? $enabled : ['authorization_code', 'client_credentials', 'refresh_token'];
    }
}
