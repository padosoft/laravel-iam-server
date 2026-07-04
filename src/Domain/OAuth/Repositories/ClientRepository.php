<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\OAuth\Repositories;

use Illuminate\Support\Facades\Hash;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use Padosoft\Iam\Domain\OAuth\ClientAssertionContext;
use Padosoft\Iam\Domain\OAuth\Entities\ClientEntity;
use Padosoft\Iam\Domain\OAuth\Models\OauthClient;
use Padosoft\Iam\Domain\Organizations\Models\Organization;

/**
 * Client store OAuth (doc 13 §4). In v1 legge da iam_oauth_clients; in M6 la fonte
 * diventa l'Application Registry manifest-driven.
 */
final class ClientRepository implements ClientRepositoryInterface
{
    // Nullable so the repo can still be constructed standalone (tests, non-token flows); when absent the
    // private_key_jwt branch simply fails closed. The container injects the shared singleton in the token flow.
    public function __construct(private readonly ?ClientAssertionContext $assertions = null) {}

    public function getClientEntity(string $clientIdentifier): ?ClientEntityInterface
    {
        $client = $this->find($clientIdentifier);

        return $client === null ? null : $this->toEntity($client);
    }

    public function validateClient(string $clientIdentifier, ?string $clientSecret, ?string $grantType): bool
    {
        $client = $this->find($clientIdentifier);
        if ($client === null) {
            return false;
        }

        // Il client deve dichiarare il grant richiesto (fail-closed).
        if ($grantType !== null && !in_array($grantType, $client->grants, true)) {
            return false;
        }

        // client_credentials è riservato ai client confidential (RFC 6749 §4.4): un client
        // public non deve poter ottenere token col solo client_id. Rigetto qui (defense-in-depth,
        // oltre al controllo isConfidential del grant league).
        if ($grantType === 'client_credentials' && !$client->is_confidential) {
            return false;
        }

        // private_key_jwt (RFC 7523): nessun secret condiviso — il client si è autenticato con un assertion
        // FIRMATO, già verificato a monte (TokenController → ClientAssertionVerifier) e stampato nel context.
        // Ci fidiamo SOLO se questa richiesta ha provato esattamente questo client_id. Il placeholder secret
        // passato da league non viene mai controllato. Fail-closed: assertion assente/non valida → context null.
        if ($client->usesPrivateKeyJwt()) {
            return $this->assertions?->verifiedClientId() === $clientIdentifier;
        }

        // Client confidential → autenticazione via secret (hash). Mai accettare secret vuoto.
        // Durante una rotazione, il secret PRECEDENTE resta valido finché non scade il grace: così l'app
        // può aggiornare la config senza downtime. La `secret_expires_at` del corrente è "soft" (guida gli
        // alert, non fa fallire l'auth qui) per non rompere un'app che non ha ancora ruotato.
        if ($client->is_confidential) {
            if (!is_string($clientSecret) || $clientSecret === '') {
                return false;
            }
            if (is_string($client->secret) && $client->secret !== '' && Hash::check($clientSecret, $client->secret)) {
                return true;
            }

            return $client->previousSecretActive() && Hash::check($clientSecret, (string) $client->secret_previous);
        }

        // Client public → nessun secret atteso (l'integrità del flusso è garantita da PKCE
        // nell'Authorization Code grant; il client_credentials è già stato escluso sopra).
        return $clientSecret === null || $clientSecret === '';
    }

    private function find(string $clientIdentifier): ?OauthClient
    {
        if ($clientIdentifier === '') {
            return null;
        }

        return OauthClient::query()
            ->where('client_id', $clientIdentifier)
            ->whereNull('revoked_at')
            ->first();
    }

    private function toEntity(OauthClient $client): ClientEntity
    {
        $identifier = $client->client_id;
        if ($identifier === '') {
            throw new \RuntimeException('client_id vuoto.');
        }

        $organizationKey = null;
        if ($client->organization_id !== null) {
            $key = Organization::query()->whereKey($client->organization_id)->value('key');
            $organizationKey = is_string($key) ? $key : null;
        }

        return new ClientEntity(
            $identifier,
            $client->name,
            $client->redirect_uris ?? [],
            $client->is_confidential,
            $client->organization_id,
            $organizationKey,
            $client->scopes,
            $client->is_first_party,
        );
    }
}
