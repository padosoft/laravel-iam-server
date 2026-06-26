<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\OAuth\Repositories;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use Padosoft\Iam\Domain\OAuth\Entities\ClientEntity;
use Padosoft\Iam\Domain\OAuth\Entities\ScopeEntity;
use Padosoft\Iam\Domain\OAuth\Models\OauthAuthCode;
use Padosoft\Iam\Domain\OAuth\Models\OauthScope;
use Padosoft\Iam\Domain\OAuth\Oidc\OidcContext;

/**
 * Catalogo scope OAuth/OIDC (doc 13 §4): scope OIDC standard + scope dichiarati dai manifest.
 * Punto di ripristino del contesto OIDC: `finalizeScopes` riceve l'authCodeId allo scambio e
 * da lì recupera nonce/auth_time per l'id_token.
 */
final class ScopeRepository implements ScopeRepositoryInterface
{
    public function __construct(private readonly OidcContext $oidc) {}

    public function getScopeEntityByIdentifier(string $identifier): ?ScopeEntityInterface
    {
        if ($identifier === '') {
            return null;
        }
        $exists = OauthScope::query()->where('identifier', $identifier)->exists();

        return $exists ? new ScopeEntity($identifier) : null;
    }

    /**
     * Restringe gli scope finali a quelli ammessi dal client: un client non può ottenere
     * scope oltre quelli che ha dichiarato (anti privilege-escalation, doc 13 §9).
     *
     * @param  ScopeEntityInterface[]  $scopes
     * @return ScopeEntityInterface[]
     */
    public function finalizeScopes(
        array $scopes,
        string $grantType,
        ClientEntityInterface $clientEntity,
        ?string $userIdentifier = null,
        ?string $authCodeId = null,
    ): array {
        // Allo scambio dell'auth code: ripristina il contesto OIDC (nonce/auth_time) e la sessione
        // (sid/acr/amr) dal code, per i claim dell'access token (sid) e dell'id_token (acr/amr).
        if ($authCodeId !== null && $authCodeId !== '') {
            $code = OauthAuthCode::query()->where('auth_code_id', $authCodeId)->first();
            if ($code !== null) {
                $this->oidc->set($code->nonce, $code->auth_time?->toDateTimeImmutable());
                $this->oidc->setSession($code->sid, $code->acr, $code->amr ?? []);
            }
        }

        $allowed = $clientEntity instanceof ClientEntity ? $clientEntity->allowedScopes : null;

        // Fail-closed: nessuno scope dichiarato → nessuno scope concesso (NON "tutti").
        if ($allowed === null) {
            return [];
        }

        // Wildcard ESPLICITO (client super-admin): solo se dichiarato con il sentinel '*'.
        if (in_array('*', $allowed, true)) {
            return array_values($scopes);
        }

        return array_values(array_filter(
            $scopes,
            static fn (ScopeEntityInterface $scope): bool => in_array($scope->getIdentifier(), $allowed, true),
        ));
    }
}
