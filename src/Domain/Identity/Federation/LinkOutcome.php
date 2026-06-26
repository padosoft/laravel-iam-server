<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Identity\Federation;

/**
 * Esito della risoluzione di un'identità federata (doc 10 §5/§6):
 *  - linked      → identità già collegata: login dell'utente
 *  - provisioned → utente creato via JIT al primo login
 *  - pending     → conflitto/policy: richiede step-up o approval, MAI link silenzioso
 */
final readonly class LinkOutcome
{
    private function __construct(
        public string $status,
        public ?string $userId,
        public ?string $federatedIdentityId,
        public ?string $reason,
    ) {}

    public static function linked(string $userId, string $federatedIdentityId): self
    {
        return new self('linked', $userId, $federatedIdentityId, null);
    }

    public static function provisioned(string $userId, string $federatedIdentityId): self
    {
        return new self('provisioned', $userId, $federatedIdentityId, null);
    }

    public static function pending(string $federatedIdentityId, string $reason): self
    {
        return new self('pending', null, $federatedIdentityId, $reason);
    }

    public function isResolved(): bool
    {
        return $this->status === 'linked' || $this->status === 'provisioned';
    }
}
