<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Audit;

use Padosoft\Iam\Contracts\Crypto\TokenSigner;
use Padosoft\Iam\Domain\Audit\Models\AuditCheckpoint;
use Padosoft\Iam\Domain\Audit\Models\AuditHead;

/**
 * Checkpoint firmati della hash-chain (doc 12 §2.2). Firma `hash(testa)` con il TokenSigner ES256
 * dell'IAM: l'hash-chain prova l'integrità INTERNA, ma un attaccante con accesso totale potrebbe
 * RICOSTRUIRE la catena da zero — la firma (non forgiabile senza la chiave privata) lo impedisce.
 */
final class AuditCheckpointer
{
    private const PURPOSE = 'iam-audit-checkpoint';

    public function __construct(private readonly TokenSigner $signer) {}

    /** Firma la testa corrente dello stream. Null se lo stream non ha ancora eventi. */
    public function checkpoint(string $stream): ?AuditCheckpoint
    {
        $head = AuditHead::query()->find($stream);
        if ($head === null || $head->seq < 1 || !is_string($head->hash) || $head->hash === '') {
            return null;
        }

        $signature = $this->signer->issue([
            'purpose' => self::PURPOSE,
            'stream' => $stream,
            'seq' => $head->seq,
            'head_hash' => $head->hash,
        ], $this->ttl());

        $checkpoint = new AuditCheckpoint;
        $checkpoint->fill([
            'stream' => $stream,
            'up_to_seq' => $head->seq,
            'head_hash' => $head->hash,
            'signature' => $signature,
            'signed_at' => now(),
        ]);
        $checkpoint->save();

        return $checkpoint;
    }

    /**
     * Verifica che la firma sia valida E che leghi esattamente lo stream/seq/head_hash della riga
     * (una manomissione dei campi senza ri-firma → mismatch; una firma forgiata → parse fallisce).
     */
    public function verify(AuditCheckpoint $checkpoint): AuditVerificationResult
    {
        try {
            $claims = $this->signer->parse($checkpoint->signature);
        } catch (\Throwable $e) {
            // Distinguiamo lo scaduto dalla firma realmente invalida: un checkpoint oltre il TTL
            // resta fail-closed ma NON è un tamper. (Anchoring esterno non-scadente = v2.)
            $cause = $this->isExpiry($e->getMessage()) ? 'checkpoint_expired' : 'checkpoint_signature_invalid';

            return AuditVerificationResult::broken(1, $checkpoint->id, 'firma del checkpoint non valida: '.$e->getMessage(), $cause);
        }

        $seqClaim = $claims['seq'] ?? null;
        $seqOk = (is_int($seqClaim) || (is_string($seqClaim) && ctype_digit($seqClaim)))
            && (int) $seqClaim === $checkpoint->up_to_seq;
        $headHashClaim = $claims['head_hash'] ?? null;

        $matches = ($claims['purpose'] ?? null) === self::PURPOSE
            && ($claims['stream'] ?? null) === $checkpoint->stream
            && $seqOk
            && is_string($headHashClaim)
            && hash_equals($headHashClaim, $checkpoint->head_hash);

        if (!$matches) {
            return AuditVerificationResult::broken(1, $checkpoint->id, 'i claim firmati non combaciano con la riga del checkpoint (manomissione)', 'tampered');
        }

        return AuditVerificationResult::ok(1);
    }

    private function isExpiry(string $message): bool
    {
        $message = strtolower($message);

        return str_contains($message, 'expired') || str_contains($message, 'scadut');
    }

    private function ttl(): int
    {
        $ttl = config('iam.audit.checkpoint_ttl_seconds', 10 * 365 * 24 * 3600);

        return is_int($ttl) && $ttl > 0 ? $ttl : 10 * 365 * 24 * 3600;
    }
}
