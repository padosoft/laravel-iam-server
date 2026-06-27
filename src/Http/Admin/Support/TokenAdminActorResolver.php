<?php

declare(strict_types=1);

namespace Padosoft\Iam\Http\Admin\Support;

use Illuminate\Http\Request;
use Padosoft\Iam\Contracts\Crypto\TokenSigner;
use Padosoft\Iam\Contracts\Support\SubjectRef;

/**
 * Risolutore di default: autentica l'Admin API con un access token IAM (Bearer) emesso da NOI. Il
 * TokenSigner valida firma ES256 + validità temporale + issuer; qui si applica l'enforcement
 * dell'audience admin (fail-closed se configurata) e si estrae il subject. È il PEP dell'Admin API.
 */
final class TokenAdminActorResolver implements AdminActorResolver
{
    public function __construct(private readonly TokenSigner $signer) {}

    public function resolve(Request $request): ?AdminContext
    {
        $bearer = $request->bearerToken();
        if (!is_string($bearer) || $bearer === '') {
            return null;
        }

        try {
            $claims = $this->signer->parse($bearer);
        } catch (\Throwable) {
            return null; // firma/scadenza/issuer non validi → non autenticato
        }

        $sub = $claims['sub'] ?? null;
        if (!is_string($sub) || $sub === '') {
            return null;
        }

        // Enforcement audience. In PRODUZIONE è obbligatoria (fail-closed): senza un'audience admin
        // configurata, un token emesso per QUALSIASI app varrebbe sull'Admin API → rifiuto. In dev/test
        // (audience non configurata) si accetta un qualunque token IAM valido per non bloccare il giro.
        $expectedAud = config('iam.admin.audience');
        $expectedAud = is_string($expectedAud) && $expectedAud !== '' ? $expectedAud : null;
        if ($expectedAud === null) {
            if (app()->environment('production')) {
                return null; // misconfiguration in prod → fail-closed, non fail-open
            }
        } elseif (!$this->audienceMatches($claims, $expectedAud)) {
            return null;
        }

        $org = $claims['org'] ?? null;
        $scopeClaim = $claims['scope'] ?? '';
        $scopes = is_string($scopeClaim) && $scopeClaim !== '' ? explode(' ', $scopeClaim) : [];

        return new AdminContext(
            actor: new SubjectRef('user', $sub),
            organizationId: is_string($org) && $org !== '' ? $org : null,
            scopes: $scopes,
        );
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    private function audienceMatches(array $claims, string $expected): bool
    {
        $aud = $claims['aud'] ?? null;
        if (is_string($aud)) {
            return $aud === $expected;
        }
        if (is_array($aud)) {
            return in_array($expected, array_filter($aud, 'is_string'), true);
        }

        return false;
    }
}
