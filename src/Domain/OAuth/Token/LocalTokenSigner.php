<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\OAuth\Token;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Ecdsa\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token\Builder;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Validator;
use Padosoft\Iam\Contracts\Crypto\KeyProvider;
use Padosoft\Iam\Contracts\Crypto\TokenSigner;
use Padosoft\Iam\Domain\OAuth\Models\SigningKey;
use Psr\Clock\ClockInterface;

/**
 * Firma JWT ES256 (EC P-256) con lcobucci/jwt. La chiave privata è custodita cifrata
 * (incartata via KeyProvider/KEK) e decifrata solo al momento della firma.
 */
final class LocalTokenSigner implements TokenSigner
{
    /** Lock atomico che serializza la generazione di chiavi 'active' (first-boot e rotate). */
    private const GENERATION_LOCK = 'iam:signing-key:generate';

    public function __construct(
        private readonly KeyProvider $keys,
        private readonly string $issuer,
        private readonly ?string $opensslConfig = null,
    ) {}

    public function issue(array $claims, int $ttlSeconds): string
    {
        $key = $this->activeKey();
        $now = new \DateTimeImmutable;

        $builder = (new Builder(new JoseEncoder, ChainedFormatter::default()))
            ->issuedBy($this->effectiveIssuer())
            ->issuedAt($now)
            ->expiresAt($now->add(new \DateInterval('PT'.max(1, $ttlSeconds).'S')))
            ->identifiedBy($this->resolveJti($claims))
            ->withHeader('kid', $key->kid);

        foreach ($claims as $name => $value) {
            // iss e i temporali (iat/exp/nbf) li impone il signer → NON sovrascrivibili (anti-spoofing).
            // jti è già stato risolto sopra (override consentito al caller fidato: es. id token league).
            if ($name === '' || in_array($name, ['iss', 'jti', 'iat', 'exp', 'nbf'], true)) {
                continue;
            }
            if ($name === 'aud') {
                $audiences = $this->audiences($value);
                if ($audiences !== []) {
                    $builder = $builder->permittedFor(...$audiences);
                }

                continue;
            }
            if ($name === 'sub') {
                $sub = $this->strVal($value);
                if ($sub !== '') {
                    $builder = $builder->relatedTo($sub);
                }

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

        // Firma (ES256) + validità temporale (exp/nbf) + issuer: accettiamo SOLO token emessi da NOI.
        // L'audience NON è validata qui: il signer non conosce l'audience attesa dal singolo resource
        // server. L'enforcement di `aud` spetta al PEP/introspection (M4b), che confronta i claim
        // restituiti con l'identità del resource server chiamante.
        $clock = new class implements ClockInterface
        {
            public function now(): \DateTimeImmutable
            {
                return new \DateTimeImmutable;
            }
        };
        $valid = (new Validator)->validate(
            $token,
            new SignedWith(new Sha256, InMemory::plainText($pem)),
            new LooseValidAt($clock),
            new IssuedBy($this->effectiveIssuer()),
        );
        if (!$valid) {
            throw new \RuntimeException('Token non valido (firma o validità temporale).');
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
        // Stesso lock di activeKey(): impedisce che rotate() e una generazione "first-boot"
        // concorrente creino due chiavi 'active'. Multi-server → richiede uno store di lock
        // atomico (redis/database/memcached); l'array store copre il singolo processo.
        $kid = Cache::lock(self::GENERATION_LOCK, 10)->block(5, fn (): string => DB::transaction(function (): string {
            SigningKey::query()->where('status', 'active')->update(['status' => 'overlap', 'rotated_at' => now()]);

            return $this->generateKey()->kid;
        }));
        if (!is_string($kid)) {
            throw new \RuntimeException('Rotazione chiave fallita.');
        }

        return $kid;
    }

    public function verificationPem(): string
    {
        $pem = $this->activeKey()->public_pem;
        if ($pem === '') {
            throw new \RuntimeException('PEM pubblica della chiave attiva vuota.');
        }

        return $pem;
    }

    private function activeKey(): SigningKey
    {
        $existing = $this->findActiveKey();
        if ($existing !== null) {
            return $existing;
        }

        // First-boot: serializza la generazione per evitare due chiavi 'active' sotto concorrenza (TOCTOU).
        // Ricontrolla DENTRO il lock: un'altra richiesta potrebbe aver già generato la chiave.
        $key = Cache::lock(self::GENERATION_LOCK, 10)->block(5, fn (): SigningKey => $this->findActiveKey() ?? $this->generateKey());
        if (!$key instanceof SigningKey) {
            throw new \RuntimeException('Generazione chiave attiva fallita.');
        }

        return $key;
    }

    private function findActiveKey(): ?SigningKey
    {
        return SigningKey::query()->where('status', 'active')->whereNull('revoked_at')->first();
    }

    /** @return non-empty-string */
    private function effectiveIssuer(): string
    {
        return $this->issuer !== '' ? $this->issuer : 'iam';
    }

    /**
     * jti del token: usa quello fornito dal caller fidato (es. identifier league per
     * introspection/revoca per jti), altrimenti ne genera uno ad alta entropia.
     *
     * @param  array<string, mixed>  $claims
     * @return non-empty-string
     */
    private function resolveJti(array $claims): string
    {
        $provided = $claims['jti'] ?? null;

        return is_string($provided) && $provided !== '' ? $provided : 'jti-'.bin2hex(random_bytes(16));
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
                'kty' => 'EC', 'crv' => 'P-256', 'use' => 'sig', 'key_ops' => ['verify'],
                'alg' => 'ES256', 'kid' => $kid,
                // Coordinate left-padded a 32 byte (P-256): un leading-zero stripped renderebbe il JWK invalido.
                'x' => $this->b64url($this->leftPad32($x)),
                'y' => $this->b64url($this->leftPad32($y)),
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

    /**
     * @return list<non-empty-string>
     */
    private function audiences(mixed $value): array
    {
        $candidates = is_array($value) ? $value : [$value];
        $out = [];
        foreach ($candidates as $candidate) {
            $s = $this->strVal($candidate);
            if ($s !== '') {
                $out[] = $s;
            }
        }

        return $out;
    }

    private function leftPad32(string $coordinate): string
    {
        return str_pad($coordinate, 32, "\x00", STR_PAD_LEFT);
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
