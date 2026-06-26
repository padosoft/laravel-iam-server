<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\OAuth;

use DateInterval;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Grant\AuthCodeGrant;
use League\OAuth2\Server\Grant\ClientCredentialsGrant;
use Padosoft\Iam\Contracts\Crypto\TokenSigner;
use Padosoft\Iam\Domain\OAuth\Grants\IamRefreshTokenGrant;
use Padosoft\Iam\Domain\OAuth\Repositories\AccessTokenRepository;
use Padosoft\Iam\Domain\OAuth\Repositories\AuthCodeRepository;
use Padosoft\Iam\Domain\OAuth\Repositories\ClientRepository;
use Padosoft\Iam\Domain\OAuth\Repositories\RefreshTokenRepository;
use Padosoft\Iam\Domain\OAuth\Repositories\ScopeRepository;

/**
 * Costruisce l'AuthorizationServer di league cablando i nostri repository e abilitando i
 * grant da config (doc 13 §6). Le state-machine restano a league; noi controlliamo solo le
 * fonti dati e il token model.
 */
final class AuthorizationServerFactory
{
    /**
     * @param  array{access_ttl?: int, auth_code_ttl?: int, refresh_ttl?: int, grants?: array<string, bool>}  $config
     */
    public function __construct(
        private readonly ClientRepository $clients,
        private readonly AccessTokenRepository $accessTokens,
        private readonly ScopeRepository $scopes,
        private readonly AuthCodeRepository $authCodes,
        private readonly RefreshTokenRepository $refreshTokens,
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
        if (($grants['authorization_code'] ?? false) === true) {
            // PKCE resta obbligatorio per i client public (default league); il refresh token
            // viene emesso nello scambio del code (consumato dal grant refresh_token).
            $authCode = new AuthCodeGrant($this->authCodes, $this->refreshTokens, $this->authCodeTtl());
            $authCode->setRefreshTokenTTL($this->refreshTtl());
            $server->enableGrantType($authCode, $this->accessTtl());
        }
        if (($grants['refresh_token'] ?? false) === true) {
            // Rotation (default league) + replay detection a livello di catena (RFC 9700).
            $refresh = new IamRefreshTokenGrant($this->refreshTokens);
            $refresh->setRefreshTokenTTL($this->refreshTtl());
            $server->enableGrantType($refresh, $this->accessTtl());
        }

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
        return new DateInterval('PT'.max(1, $this->config['access_ttl'] ?? 900).'S');
    }

    private function authCodeTtl(): DateInterval
    {
        return new DateInterval('PT'.max(1, $this->config['auth_code_ttl'] ?? 600).'S');
    }

    private function refreshTtl(): DateInterval
    {
        return new DateInterval('PT'.max(1, $this->config['refresh_ttl'] ?? 1209600).'S');
    }
}
