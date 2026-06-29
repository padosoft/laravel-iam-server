<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Authorization\Pdp;

/**
 * Riferimento a una risorsa (oggetto) del grafo ReBAC: tipo + id applicativi (es. doc:42, folder:7).
 * Server-side: il contratto AuthorizationEngine espone le risorse come array{type,id} per non
 * accoppiare i client al value object.
 */
final readonly class ResourceRef implements \Stringable
{
    public function __construct(
        public string $type,
        public string $id,
    ) {}

    public function __toString(): string
    {
        return "{$this->type}:{$this->id}";
    }
}
