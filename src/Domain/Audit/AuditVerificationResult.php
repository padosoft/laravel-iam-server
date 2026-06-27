<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Audit;

/**
 * Esito della verifica di integrità di una hash-chain (doc 12 §2.4). Se non valido, riporta il
 * PRIMO punto di rottura (uuid + motivo) — l'evidenza forense parte da lì.
 */
final class AuditVerificationResult
{
    public function __construct(
        public readonly bool $valid,
        public readonly int $checked,
        public readonly ?string $firstBrokenUuid = null,
        public readonly ?string $reason = null,
    ) {}

    public static function ok(int $checked): self
    {
        return new self(true, $checked);
    }

    public static function broken(int $checked, ?string $uuid, string $reason): self
    {
        return new self(false, $checked, $uuid, $reason);
    }
}
