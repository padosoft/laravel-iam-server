<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\OAuth\Token;

use League\OAuth2\Server\Entities\ScopeEntityInterface;
use Padosoft\Iam\Contracts\Assurance\Aal;
use Padosoft\Iam\Domain\Identity\Models\Session;
use Padosoft\Iam\Domain\OAuth\Entities\AccessTokenEntity;
use Padosoft\Iam\Domain\OAuth\Entities\ClientEntity;
use Padosoft\Iam\Domain\OAuth\Oidc\OidcContext;
use Padosoft\Iam\Domain\Organizations\Models\Organization;

/**
 * Costruisce il claim set custom dell'access token IAM (doc 13 §5): oltre ai claim OAuth
 * standard aggiunge `policy_version` (consistency token del PDP, doc 09 §6), `org` e
 * `client_id`, così il PEP sa se la sua cache è aggiornata e per quale tenant vale il token.
 */
final class AccessTokenClaims
{
    public function __construct(
        private readonly OidcContext $oidc,
        private readonly ?TokenIssuanceContext $issuance = null,
    ) {}

    /**
     * @return array<string, mixed>
     */
    public function build(AccessTokenEntity $token): array
    {
        $client = $token->getClient();
        $clientId = $client->getIdentifier();
        $subject = $token->getUserIdentifier() ?? $clientId;

        $scopes = array_map(
            static fn (ScopeEntityInterface $scope): string => $scope->getIdentifier(),
            $token->getScopes(),
        );

        $claims = [
            'jti' => $token->getIdentifier(),
            'sub' => $subject,
            'aud' => $clientId,           // audience-specific: il token vale per la app del client
            'client_id' => $clientId,
            'scope' => implode(' ', $scopes),
        ];

        $organizationId = $client instanceof ClientEntity ? $client->organizationId : null;
        if ($client instanceof ClientEntity && $client->organizationKey !== null) {
            $claims['org'] = $client->organizationKey;
        }
        $claims['policy_version'] = $this->policyVersion($organizationId);

        // sid: lega l'access token alla sessione server-side (revoca prima della scadenza, doc 10 §3).
        $sid = $this->oidc->sid();
        if ($sid !== null) {
            $claims['sid'] = $sid;

            // IAM-04: porta l'AAL della sessione NELL'ACCESS TOKEN. acr/amr stanno sull'id_token, ma
            // l'enforcement server-side (Admin gate → step-up) legge l'AAL dall'access token: senza questo
            // claim un attore che ha fatto step-up varrebbe comunque aal1 e ogni rotta requires_step_up
            // resterebbe bloccata.
            // IAM-19: applica QUI la finestra di FRESHNESS dello step-up. Senza, un refresh ri-minterebbe un
            // aal2 fresco da un'elevazione ormai scaduta e il gate (che si fida del claim) onorerebbe uno
            // step-up ben oltre la sua finestra: il refresh diventerebbe un rinnovo perpetuo dell'AAL elevato.
            $session = Session::query()->whereKey($sid)->first();
            if ($session !== null) {
                $claims['aal'] = $this->effectiveAal($session);
            }
        }

        // Delega AI agents (RFC 8693): il grant token-exchange (modulo -agents) deposita
        // act/pds_dgr/audience nel TokenIssuanceContext; l'applicazione è guardata dalle
        // chiavi riservate (vedi TokenIssuanceContext::RESERVED — mai override di sub/scope/...).
        if ($this->issuance !== null) {
            $claims = $this->issuance->apply($claims);
        }

        return $claims;
    }

    /**
     * AAL effettivo da stampare: il livello della sessione, declassato ad AAL1 se un'elevazione via step-up
     * è scaduta (IAM-19). Allineato a {@see NativeAssuranceProvider::currentAal}.
     */
    private function effectiveAal(Session $session): string
    {
        $level = Aal::fromString($session->aal);
        if ($level->rank() > Aal::AAL1->rank() && !$this->stepUpFresh($session)) {
            return Aal::AAL1->value;
        }

        return $level->value;
    }

    /**
     * IAM-19 freshness, coerente con {@see NativeAssuranceProvider::stepUpFresh}: `step_up_at` nullo =
     * livello di autenticazione INIZIALE (non un'elevazione) → non scade. Finestra <= 0 = freschezza off.
     */
    private function stepUpFresh(Session $session): bool
    {
        $stepUpAt = $session->step_up_at;
        if ($stepUpAt === null) {
            return true;
        }
        $window = config('iam.authentication.session.step_up_freshness', 900);
        $window = is_numeric($window) ? (int) $window : 900;
        if ($window <= 0) {
            return true;
        }

        return abs($stepUpAt->diffInSeconds(now())) <= $window;
    }

    /** Allineato a NativeSqlEngine::policyVersion (doc 09 §6): consistency token per-org. */
    private function policyVersion(?string $organizationId): int
    {
        if ($organizationId === null) {
            return 0;
        }
        $value = Organization::query()->whereKey($organizationId)->value('policy_version');

        return is_numeric($value) ? (int) $value : 0;
    }
}
