<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\OAuth;

use Illuminate\Contracts\Cache\Repository as Cache;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Ecdsa\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Validator;
use Padosoft\Iam\Domain\OAuth\Models\OauthClient;

/**
 * Verifies a **private_key_jwt** client assertion (RFC 7523 / OIDC core §9) — asymmetric client
 * authentication with NO shared secret. The client signs a short-lived JWT with its private key; we verify
 * it against the PUBLIC key the client registered (its JWKS). Every failure returns null (fail-closed) — a
 * client is authenticated only when the signature AND every registered claim check out.
 *
 * Checks, in order: iss === sub === a known private_key_jwt client · alg ES256 · signature verifies against
 * the client's registered EC P-256 public key · `aud` names this token endpoint · not expired / not yet
 * valid · `jti` is single-use (replay-protected until the assertion expires).
 */
final class ClientAssertionVerifier
{
    /** The RFC 7523 client-assertion type this verifier handles. */
    public const ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

    public function __construct(
        private readonly Cache $cache,
        /** Reject assertions whose lifetime (exp − iat) exceeds this — a stolen assertion stays useful only briefly. */
        private readonly int $maxLifetimeSeconds = 300,
    ) {}

    /**
     * @param  list<string>  $audiences  acceptable `aud` values (this token endpoint URL and/or the issuer)
     * @return string|null the authenticated client_id, or null on ANY failure
     */
    public function verify(string $assertion, array $audiences): ?string
    {
        try {
            return $this->doVerify($assertion, $audiences);
        } catch (\Throwable) {
            return null; // fail-closed: never leak why, never authenticate on error
        }
    }

    /** @param list<string> $audiences */
    private function doVerify(string $assertion, array $audiences): ?string
    {
        if ($assertion === '') {
            return null;
        }
        $token = (new Parser(new JoseEncoder))->parse($assertion);
        if (!$token instanceof UnencryptedToken) {
            return null;
        }

        $claims = $token->claims();
        $iss = $claims->get('iss');
        $sub = $claims->get('sub');
        // RFC 7523 §3: for client auth, iss and sub are both the client_id.
        if (!is_string($iss) || $iss === '' || $iss !== $sub) {
            return null;
        }

        $client = OauthClient::query()->where('client_id', $iss)->whereNull('revoked_at')->first();
        if ($client === null || !$client->usesPrivateKeyJwt() || !is_array($client->jwks)) {
            return null;
        }

        // Only ES256 (P-256) — the algorithm used across this ecosystem. No `alg: none`, no downgrade.
        if ($token->headers()->get('alg') !== 'ES256') {
            return null;
        }

        $kid = $token->headers()->get('kid');
        $pem = $this->jwkToPem($this->selectJwk($client->jwks, is_string($kid) ? $kid : null));
        if ($pem === null || $pem === '') {
            return null;
        }

        // Cryptographic verification against the registered public key.
        if (!(new Validator)->validate($token, new SignedWith(new Sha256, InMemory::plainText($pem)))) {
            return null;
        }

        // aud must name this token endpoint (prevents an assertion minted for another server being replayed here).
        $aud = $claims->get('aud');
        $audList = array_values(array_filter(is_array($aud) ? $aud : [$aud], 'is_string'));
        if (array_intersect($audiences, $audList) === []) {
            return null;
        }

        // Temporal validity: exp required and in the future; nbf (if present) already reached; bounded lifetime.
        $now = time();
        $exp = $claims->get('exp');
        if (!$exp instanceof \DateTimeInterface || $exp->getTimestamp() <= $now) {
            return null;
        }
        $nbf = $claims->get('nbf');
        if ($nbf instanceof \DateTimeInterface && $nbf->getTimestamp() > $now + 5) {
            return null;
        }
        $iat = $claims->get('iat');
        if ($iat instanceof \DateTimeInterface && $exp->getTimestamp() - $iat->getTimestamp() > $this->maxLifetimeSeconds) {
            return null;
        }

        // Replay protection: a jti is single-use until the assertion expires (atomic add → false if seen).
        $jti = $claims->get('jti');
        if (!is_string($jti) || $jti === '') {
            return null;
        }
        $ttl = max(1, $exp->getTimestamp() - $now);
        if ($this->cache->add('iam:pkjwt:jti:'.hash('sha256', $iss.'|'.$jti), true, $ttl) === false) {
            return null; // this assertion was already used
        }

        return $iss;
    }

    /**
     * Pick the registered JWK: by `kid` when the assertion carries one, otherwise the sole EC key.
     *
     * @param  array<array-key, mixed>  $jwks
     * @return array<array-key, mixed>|null
     */
    private function selectJwk(array $jwks, ?string $kid): ?array
    {
        $keys = $jwks['keys'] ?? null;
        if (!is_array($keys)) {
            return null;
        }
        $ecKeys = array_values(array_filter($keys, static fn ($k): bool => is_array($k) && ($k['kty'] ?? null) === 'EC'));

        if ($kid !== null) {
            foreach ($ecKeys as $k) {
                if (($k['kid'] ?? null) === $kid) {
                    return $k;
                }
            }

            return null; // a kid was named but no key matches → fail-closed (don't fall back to another key)
        }

        return count($ecKeys) === 1 ? $ecKeys[0] : null; // no kid: only unambiguous when there's exactly one key
    }

    /**
     * Convert an EC P-256 public JWK (x, y) into a PEM SubjectPublicKeyInfo the ES256 verifier can use.
     *
     * @param  array<array-key, mixed>|null  $jwk
     */
    private function jwkToPem(?array $jwk): ?string
    {
        if ($jwk === null || ($jwk['kty'] ?? null) !== 'EC' || ($jwk['crv'] ?? null) !== 'P-256') {
            return null;
        }
        $x = self::b64uDecode(is_string($jwk['x'] ?? null) ? $jwk['x'] : '');
        $y = self::b64uDecode(is_string($jwk['y'] ?? null) ? $jwk['y'] : '');
        if (strlen($x) !== 32 || strlen($y) !== 32) {
            return null;
        }
        // SubjectPublicKeyInfo DER for prime256v1 + the uncompressed point (0x04 || x || y).
        $der = (string) hex2bin('3059301306072a8648ce3d020106082a8648ce3d030107034200')."\x04".$x.$y;

        return "-----BEGIN PUBLIC KEY-----\n".chunk_split(base64_encode($der), 64, "\n")."-----END PUBLIC KEY-----\n";
    }

    private static function b64uDecode(string $value): string
    {
        return (string) base64_decode(strtr($value, '-_', '+/'), true);
    }
}
