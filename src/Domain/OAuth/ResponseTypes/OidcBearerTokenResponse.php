<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\OAuth\ResponseTypes;

use DateTimeImmutable;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\ResponseTypes\BearerTokenResponse;
use Padosoft\Iam\Contracts\Crypto\TokenSigner;
use Padosoft\Iam\Domain\OAuth\Oidc\OidcContext;

/**
 * Response Bearer con id_token OIDC (doc 13 §5): quando lo scope include `openid` e il token è
 * legato a un utente, aggiunge un id_token firmato (stesso TokenSigner ES256 + JWKS) con
 * sub/aud=client_id/auth_time e — se presente — nonce (anti-replay). acr/amr → M5 (AAL/metodi).
 */
final class OidcBearerTokenResponse extends BearerTokenResponse
{
    public function __construct(
        private readonly TokenSigner $signer,
        private readonly OidcContext $context,
        private readonly int $idTokenTtl,
    ) {}

    /**
     * @return array<array-key, mixed>
     */
    protected function getExtraParams(AccessTokenEntityInterface $accessToken): array
    {
        $scopes = array_map(
            static fn (ScopeEntityInterface $scope): string => $scope->getIdentifier(),
            $accessToken->getScopes(),
        );
        if (!in_array('openid', $scopes, true)) {
            return [];
        }

        // id_token solo per token legati a un utente (no client_credentials).
        $sub = $accessToken->getUserIdentifier();
        if ($sub === null || $sub === '') {
            return [];
        }

        $claims = [
            'sub' => $sub,
            'aud' => $accessToken->getClient()->getIdentifier(),
            'auth_time' => ($this->context->authTime() ?? new DateTimeImmutable)->getTimestamp(),
        ];
        $nonce = $this->context->nonce();
        if ($nonce !== null) {
            $claims['nonce'] = $nonce;
        }
        // acr/amr: livello di assurance (AAL) e metodi di autenticazione della sessione (doc 10 §4).
        $acr = $this->context->acr();
        if ($acr !== null) {
            $claims['acr'] = $acr;
        }
        $amr = $this->context->amr();
        if ($amr !== []) {
            $claims['amr'] = $amr;
        }
        $sid = $this->context->sid();
        if ($sid !== null) {
            $claims['sid'] = $sid;
        }

        return ['id_token' => $this->signer->issue($claims, $this->idTokenTtl)];
    }
}
