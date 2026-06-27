<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Audit;

use Padosoft\Iam\Domain\Audit\Models\AuditEvent;
use Padosoft\Iam\Domain\Audit\Models\AuditHead;

/**
 * Verifica l'integrità di una hash-chain (doc 12 §2.4): ricalcola hash/prev_hash riga per riga e
 * controlla la contiguità di `seq`. Ritorna OK oppure il PRIMO punto di rottura (manomissione di un
 * campo, hash incoerente, link spezzato o buco nella sequenza = cancellazione/riordino).
 */
final class AuditChainVerifier
{
    public function __construct(private readonly AuditHasher $hasher) {}

    public function verify(string $stream): AuditVerificationResult
    {
        $prevHash = AuditHasher::GENESIS;
        $expectedSeq = 1;
        $checked = 0;

        /** @var iterable<AuditEvent> $events */
        $events = AuditEvent::query()
            ->where('stream', $stream)
            ->orderBy('seq')
            ->cursor();

        foreach ($events as $event) {
            $checked++;

            // Buco/riordino nella sequenza: un seq mancante o fuori ordine è già manomissione.
            if ($event->seq !== $expectedSeq) {
                return AuditVerificationResult::broken(
                    $checked,
                    $event->uuid,
                    "seq atteso {$expectedSeq}, trovato {$event->seq} (buco o riordino nella catena)",
                );
            }

            // Il link col precedente deve combaciare.
            if ($event->prev_hash !== $prevHash) {
                return AuditVerificationResult::broken($checked, $event->uuid, 'prev_hash non combacia con la testa precedente');
            }

            // L'hash memorizzato deve corrispondere al ricalcolo sui dati attuali della riga.
            $recomputed = $this->hasher->hash($event->canonicalPayload(), $event->prev_hash);
            if (!hash_equals($recomputed, (string) $event->hash)) {
                return AuditVerificationResult::broken($checked, $event->uuid, 'hash ricalcolato diverso (riga manomessa)');
            }

            $prevHash = $event->hash;
            $expectedSeq++;
        }

        // Troncamento di coda: cancellare gli ultimi N eventi lascia un prefisso valido, ma la testa
        // dello stream punta ancora alla coda rimossa. Confrontiamo l'ultimo hash ricalcolato (e il
        // seq) con `iam_audit_heads` → una coda mancante è rilevabile quanto un buco interno.
        $head = AuditHead::query()->find($stream);
        if ($head === null) {
            // Head assente ma esistono eventi → la testa è stata cancellata: fail-closed (non OK).
            if ($checked > 0) {
                return AuditVerificationResult::broken($checked, null, 'testa dello stream assente con eventi presenti (head cancellata)', 'head_missing');
            }
        } else {
            $headHash = is_string($head->hash) && $head->hash !== '' ? $head->hash : AuditHasher::GENESIS;
            if (!hash_equals($prevHash, $headHash) || $head->seq !== $checked) {
                return AuditVerificationResult::broken($checked, null, 'coda troncata: la testa dello stream non combacia con l\'ultimo evento', 'tail_truncated');
            }
        }

        return AuditVerificationResult::ok($checked);
    }
}
