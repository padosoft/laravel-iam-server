<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\OAuth\Entities;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\Traits\ClientTrait;
use League\OAuth2\Server\Entities\Traits\EntityTrait;

/**
 * Client OAuth per league. Porta con sé il contesto IAM (org + scope ammessi) per
 * evitare query ripetute durante l'emissione del token (doc 13 §4).
 */
final class ClientEntity implements ClientEntityInterface
{
    use ClientTrait;
    use EntityTrait;

    /**
     * @param  non-empty-string  $identifier
     * @param  string|string[]  $redirectUri
     * @param  list<string>|null  $allowedScopes
     */
    public function __construct(
        string $identifier,
        string $name,
        string|array $redirectUri,
        bool $isConfidential,
        public readonly ?string $organizationId = null,
        public readonly ?string $organizationKey = null,
        public readonly ?array $allowedScopes = null,
        public readonly bool $isFirstParty = true,
    ) {
        $this->identifier = $identifier;
        $this->name = $name;
        $this->redirectUri = $redirectUri;
        $this->isConfidential = $isConfidential;
    }
}
