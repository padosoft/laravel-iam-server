<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\OAuth\Entities;

use League\OAuth2\Server\CryptKeyInterface;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\TokenEntityTrait;
use Padosoft\Iam\Contracts\Crypto\TokenSigner;
use Padosoft\Iam\Domain\OAuth\Token\AccessTokenClaims;

/**
 * Access token IAM. A differenza del default league (RSA via CryptKey), la firma è
 * delegata al NOSTRO {@see TokenSigner} (ES256/EC P-256 + kid nel JWKS + rotazione, M4a)
 * con i claim custom (policy_version, org, ...). Così c'è un'unica catena di firma/rotazione.
 */
final class AccessTokenEntity implements AccessTokenEntityInterface
{
    use EntityTrait;
    use TokenEntityTrait;

    public function __construct(
        private readonly TokenSigner $signer,
        private readonly AccessTokenClaims $claims,
    ) {}

    /**
     * No-op: league inietta qui la sua chiave privata, ma noi NON la usiamo per firmare
     * (lo fa il TokenSigner). Vedi AuthorizationServerFactory::placeholderKey.
     */
    public function setPrivateKey(CryptKeyInterface $privateKey): void
    {
        // intenzionalmente vuoto.
    }

    public function toString(): string
    {
        $ttl = $this->getExpiryDateTime()->getTimestamp() - time();

        return $this->signer->issue($this->claims->build($this), max(1, $ttl));
    }
}
