<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Authorization\Pdp;

use Padosoft\Iam\Contracts\Support\SubjectRef;

/**
 * Query di decisione del PDP (doc 09 §5). `permission` è il full_key richiesto
 * (es. warehouse:stock.adjust).
 */
final readonly class DecisionQuery
{
    /** @param array<string, mixed> $context */
    public function __construct(
        public SubjectRef $subject,
        public string $permission,
        public ?string $organizationId = null,
        public ?string $applicationKey = null,
        public ?string $resourceRef = null,
        public array $context = [],
        public string $currentAal = 'aal1',
        public bool $explain = false,
    ) {}
}
