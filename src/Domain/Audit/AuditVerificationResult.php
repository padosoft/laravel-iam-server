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
        public readonly ?string $cause = null,
        // IAM-07: true only when the head is anchored by a valid ES256-signed checkpoint (the one
        // artifact a DB-write attacker cannot forge). A chain can be internally consistent yet
        // unanchored (no checkpoint yet) — that is `valid=true, anchored=false`, an honest signal to
        // auditors that the result rests on the writable DB alone, not on a signature.
        public readonly bool $anchored = false,
    ) {}

    public static function ok(int $checked, bool $anchored = false): self
    {
        return new self(true, $checked, anchored: $anchored);
    }

    /**
     * `$cause` categorizza la rottura per i caller: es. 'tampered' (campo alterato), 'gap'
     * (buco/riordino), 'tail_truncated', 'checkpoint_expired', 'checkpoint_signature_invalid'.
     * Fail-closed in ogni caso (valid=false), ma un auditor distingue uno scaduto da un tamper.
     */
    public static function broken(int $checked, ?string $uuid, string $reason, ?string $cause = null): self
    {
        return new self(false, $checked, $uuid, $reason, $cause);
    }
}
