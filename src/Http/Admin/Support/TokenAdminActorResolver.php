<?php

declare(strict_types=1);

namespace Padosoft\Iam\Http\Admin\Support;

use Illuminate\Http\Request;
use Padosoft\Iam\Contracts\Assurance\Aal;
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
            // IAM-13: fail-CLOSED by default when no admin audience is configured. Only the explicit
            // dev/test environments tolerate a missing audience; any other APP_ENV — production, staging,
            // `prod`, `production-eu`, or any unrecognised string — rejects. A misconfiguration must never
            // widen access, and the old exact-string `production` check fell open for every other value.
            if (!app()->environment('local', 'testing')) {
                return null;
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
            aal: $this->assuranceLevel($claims),
        );
    }

    /**
     * Livello di assurance dell'attore, per l'enforcement dello step-up sull'Admin API (IAM-04).
     * Fonte: claim `aal` esplicito, altrimenti `acr` (OIDC). Normalizzato via Aal::fromString che
     * fa fail-closed su valori assenti/sconosciuti → `aal1` (il livello più basso).
     *
     * @param  array<string, mixed>  $claims
     */
    private function assuranceLevel(array $claims): string
    {
        $raw = $claims['aal'] ?? $claims['acr'] ?? null;

        return Aal::fromString(is_string($raw) ? $raw : null)->value;
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
