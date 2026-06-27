<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Audit\Pii;

use Padosoft\Iam\Contracts\Crypto\SecretCipher;
use Padosoft\Iam\Domain\Audit\AuditChainAppender;

/**
 * Diritto all'oblio GDPR via crypto-shredding (doc 12 §7). Distruggere la DEK del soggetto rende
 * la sua PII illeggibile SENZA alterare le righe di audit (l'hash è sul ciphertext) → concilia
 * append-only immutabile e right-to-erasure. Un legal hold attivo lo sospende. L'azione stessa è
 * registrata come meta-evento (senza PII).
 */
final class SubjectEraser
{
    public function __construct(
        private readonly SecretCipher $cipher,
        private readonly AuditChainAppender $appender,
        private readonly AuditRecorder $recorder,
    ) {}

    /**
     * @throws LegalHoldActive se il soggetto è sotto legal hold attivo
     */
    public function erase(string $subject): void
    {
        if ($this->hasActiveLegalHold($subject)) {
            throw LegalHoldActive::for($subject);
        }

        // 1. Distruggi la DEK del soggetto → PII illeggibile (irreversibile).
        $this->cipher->shred($this->recorder->scope($subject));

        // 2. Registra l'erasure come meta-evento, SENZA PII (è la prova dell'azione GDPR stessa).
        $this->appender->append([
            'stream' => 'global',
            'event_type' => 'subject.erased',
            'target_type' => 'subject',
            'target_id' => $subject,
            'risk_level' => 'high',
            'metadata_json' => ['reason' => 'gdpr-erasure'],
        ]);
    }

    public function placeLegalHold(string $subject, string $reason): LegalHold
    {
        $hold = new LegalHold;
        $hold->fill(['subject' => $subject, 'reason' => $reason, 'placed_at' => now()]);
        $hold->save();

        return $hold;
    }

    public function releaseLegalHold(string $subject): void
    {
        LegalHold::query()
            ->where('subject', $subject)
            ->whereNull('released_at')
            ->update(['released_at' => now()]);
    }

    public function hasActiveLegalHold(string $subject): bool
    {
        return LegalHold::query()
            ->where('subject', $subject)
            ->whereNull('released_at')
            ->exists();
    }
}
