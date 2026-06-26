<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\OAuth\Token;

use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Ecdsa\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token\Builder;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Validator;
use Padosoft\Iam\Contracts\Crypto\KeyProvider;
use Padosoft\Iam\Contracts\Crypto\TokenSigner;
use Padosoft\Iam\Domain\OAuth\Models\SigningKey;

/**
 * Firma JWT ES256 (EC P-256) con lcobucci/jwt. La chiave privata è custodita cifrata
 * (incartata via KeyProvider/KEK) e decifrata solo al momento della firma.
 */
final class LocalTokenSigner implements TokenSigner
{
    public function __construct(
        private readonly KeyProvider $keys,
        private readonly string $issuer,
        private readonly ?string $opensslConfig = null,
    ) {}

    public function issue(array $claims, int $ttlSeconds): string
    {
        $key = $this->activeKey();
        $now = new \DateTimeImmutable;
        $issuer = $this->issuer !== '' ? $this->issuer : 'iam';

        $builder = (new Builder(new JoseEncoder, ChainedFormatter::default()))
            ->issuedBy($issuer)
            ->issuedAt($now)
            ->expiresAt($now->add(new \DateInterval('PT'.max(1, $ttlSeconds).'S')))
            ->identifiedBy('jti_'.bin2hex(random_bytes(8)))
            ->withHeader('kid', $key->kid);

        foreach ($claims as $name => $value) {
            // iat/exp/nbf sono già impostati sopra; nomi vuoti ignorati.
            if ($name === '' || in_array($name, ['iat', 'exp', 'nbf'], true)) {
                continue;
            }
            if (in_array($name, ['sub', 'aud', 'iss', 'jti'], true)) {
                $registered = $this->strVal($value);
                if ($registered === '') {
                    continue;
                }
                $builder = match ($name) {
                    'sub' => $builder->relatedTo($registered),
                    'aud' => $builder->permittedFor($registered),
                    'iss' => $builder->issuedBy($registered),
                    default => $builder->identifiedBy($registered), // jti
                };

                continue;
            }
            $builder = $builder->withClaim($name, $value);
        }

        $pem = $this->privatePem($key);
        if ($pem === '') {
            throw new \RuntimeException('Chiave privata vuota.');
        }

        return $builder->getToken(new Sha256, InMemory::plainText($pem))->toString();
    }

    public function parse(string $jwt): array
    {
        if ($jwt === '') {
            throw new \RuntimeException('JWT vuoto.');
        }
        $token = (new Parser(new JoseEncoder))->parse($jwt);
        if (!$token instanceof UnencryptedToken) {
            throw new \RuntimeException('Token non valido.');
        }

        $kid = $token->headers()->get('kid');
        if (!is_string($kid)) {
            throw new \RuntimeException('Token senza kid.');
        }

        $key = SigningKey::query()->where('kid', $kid)->whereNull('revoked_at')->first();
        if ($key === null) {
            throw new \RuntimeException("kid {$kid} sconosciuto o revocato.");
        }

        $pem = $key->public_pem;
        if ($pem === '') {
            throw new \RuntimeException('PEM pubblica vuota.');
        }
        $valid = (new Validator)->validate(
            $token,
            new SignedWith(new Sha256, InMemory::plainText($pem)),
        );
        if (!$valid) {
            throw new \RuntimeException('Firma del token non valida.');
        }
        if ($token->isExpired(new \DateTimeImmutable)) {
            throw new \RuntimeException('Token scaduto.');
        }

        return $token->claims()->all();
    }

    public function jwks(): array
    {
        $keys = SigningKey::query()
            ->whereNull('revoked_at')
            ->whereIn('status', ['active', 'overlap'])
            ->get();

        $jwks = [];
        foreach ($keys as $key) {
            $jwks[] = $key->public_jwk;
        }

        return $jwks;
    }

    public function rotate(): string
    {
        SigningKey::query()->where('status', 'active')->update(['status' => 'overlap', 'rotated_at' => now()]);

        return $this->generateKey()->kid;
    }

    private function activeKey(): SigningKey
    {
        return SigningKey::query()->where('status', 'active')->whereNull('revoked_at')->first()
            ?? $this->generateKey();
    }

    private function generateKey(): SigningKey
    {
        $options = ['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1'];
        if ($this->opensslConfig !== null) {
            $options['config'] = $this->opensslConfig;
        }

        $resource = openssl_pkey_new($options);
        if ($resource === false) {
            throw new \RuntimeException('Generazione chiave EC fallita: '.(openssl_error_string() ?: 'errore openssl'));
        }

        $privatePem = '';
        if (!openssl_pkey_export($resource, $privatePem, null, $options) || !is_string($privatePem)) {
            throw new \RuntimeException('Export chiave privata EC fallito.');
        }

        $details = openssl_pkey_get_details($resource);
        $publicPem = $details['key'] ?? null;
        $ec = $details['ec'] ?? null;
        if (!is_string($publicPem) || !is_array($ec)) {
            throw new \RuntimeException('Dettagli chiave EC non disponibili.');
        }
        $x = $ec['x'] ?? null;
        $y = $ec['y'] ?? null;
        if (!is_string($x) || !is_string($y)) {
            throw new \RuntimeException('Coordinate EC mancanti.');
        }

        $kid = 'sk_'.bin2hex(random_bytes(8));

        return SigningKey::query()->create([
            'kid' => $kid,
            'alg' => 'ES256',
            'public_jwk' => [
                'kty' => 'EC', 'crv' => 'P-256', 'use' => 'sig', 'alg' => 'ES256', 'kid' => $kid,
                'x' => $this->b64url($x), 'y' => $this->b64url($y),
            ],
            'public_pem' => $publicPem,
            'private_wrapped' => json_encode($this->keys->wrapDataKey($privatePem), JSON_THROW_ON_ERROR),
            'status' => 'active',
        ]);
    }

    private function privatePem(SigningKey $key): string
    {
        $decoded = json_decode($key->private_wrapped, true, 512, JSON_THROW_ON_ERROR);
        if (!is_array($decoded)) {
            throw new \RuntimeException('private_wrapped corrotto.');
        }
        $ciphertext = $decoded['ciphertext'] ?? null;
        $keyId = $decoded['key_id'] ?? null;
        $keyVersion = $decoded['key_version'] ?? null;
        if (!is_string($ciphertext) || !is_string($keyId) || !is_int($keyVersion)) {
            throw new \RuntimeException('private_wrapped non valido.');
        }

        return $this->keys->unwrapDataKey([
            'ciphertext' => $ciphertext,
            'key_id' => $keyId,
            'key_version' => $keyVersion,
        ]);
    }

    private function b64url(string $bin): string
    {
        return rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
    }

    private function strVal(mixed $value): string
    {
        return is_scalar($value) ? (string) $value : '';
    }
}
