<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Authorization\Pdp;

/**
 * Esito di un check ReBAC: vale o no + il cammino nel grafo che lo giustifica (per explain/audit).
 */
final readonly class RelationResult
{
    /** @param list<string> $path passi del grafo, es. "user:mario —member→ group:eng" */
    public function __construct(
        public bool $holds,
        public array $path = [],
    ) {}

    public static function deny(): self
    {
        return new self(false);
    }
}
