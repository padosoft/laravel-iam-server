<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\OAuth\Repositories;

use Illuminate\Support\Facades\Hash;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use Padosoft\Iam\Domain\OAuth\Entities\ClientEntity;
use Padosoft\Iam\Domain\OAuth\Models\OauthClient;
use Padosoft\Iam\Domain\Organizations\Models\Organization;

/**
 * Client store OAuth (doc 13 §4). In v1 legge da iam_oauth_clients; in M6 la fonte
 * diventa l'Application Registry manifest-driven.
 */
final class ClientRepository implements ClientRepositoryInterface
{
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

        // Client confidential → autenticazione via secret (hash). Mai accettare secret vuoto.
        if ($client->is_confidential) {
            return is_string($client->secret) && $client->secret !== ''
                && is_string($clientSecret) && $clientSecret !== ''
                && Hash::check($clientSecret, $client->secret);
        }

        // Client public → nessun secret atteso (l'integrità è garantita da PKCE nel grant).
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
        );
    }
}
