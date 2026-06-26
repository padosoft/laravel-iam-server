<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\OAuth;

use DateInterval;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Grant\ClientCredentialsGrant;
use Padosoft\Iam\Contracts\Crypto\TokenSigner;
use Padosoft\Iam\Domain\OAuth\Repositories\AccessTokenRepository;
use Padosoft\Iam\Domain\OAuth\Repositories\ClientRepository;
use Padosoft\Iam\Domain\OAuth\Repositories\ScopeRepository;

/**
 * Costruisce l'AuthorizationServer di league cablando i nostri repository e abilitando i
 * grant da config (doc 13 §6). Le state-machine restano a league; noi controlliamo solo le
 * fonti dati e il token model.
 */
final class AuthorizationServerFactory
{
    /**
     * @param  array{access_ttl?: int, grants?: array<string, bool>}  $config
     */
    public function __construct(
        private readonly ClientRepository $clients,
        private readonly AccessTokenRepository $accessTokens,
        private readonly ScopeRepository $scopes,
        private readonly TokenSigner $signer,
        private readonly string $encryptionKey,
        private readonly array $config,
    ) {}

    public function make(): AuthorizationServer
    {
        $server = new AuthorizationServer(
            $this->clients,
            $this->accessTokens,
            $this->scopes,
            $this->placeholderKey(),
            $this->encryptionKey,
        );

        $grants = $this->config['grants'] ?? [];
        if (($grants['client_credentials'] ?? false) === true) {
            $server->enableGrantType(new ClientCredentialsGrant, $this->accessTtl());
        }
        // authorization_code + refresh_token → slice M4b.2 / M4b.3.

        return $server;
    }

    /**
     * league richiede una CryptKey valida ma NON firma i nostri access token: lo fa il
     * TokenSigner (ES256 + kid nel JWKS). Passiamo quindi la PEM PUBBLICA della chiave attiva
     * come placeholder valido e non segreto (è già esposta nel JWKS).
     */
    private function placeholderKey(): CryptKey
    {
        return new CryptKey($this->signer->verificationPem(), null, false);
    }

    private function accessTtl(): DateInterval
    {
        $seconds = $this->config['access_ttl'] ?? 900;

        return new DateInterval('PT'.max(1, $seconds).'S');
    }
}
