<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Audit;

use Padosoft\Iam\Domain\Audit\Models\AuditCheckpoint;
use Padosoft\Iam\Domain\Audit\Models\AuditEvent;
use Padosoft\Iam\Domain\Audit\Models\AuditHead;

/**
 * Verifica l'integrità di una hash-chain (doc 12 §2.4): ricalcola hash/prev_hash riga per riga e
 * controlla la contiguità di `seq`. Ritorna OK oppure il PRIMO punto di rottura (manomissione di un
 * campo, hash incoerente, link spezzato o buco nella sequenza = cancellazione/riordino).
 *
 * IAM-07: l'hash-chain è un SHA-256 non-keyed e la testa (`iam_audit_heads`) vive nello stesso DB
 * scrivibile che deve proteggere — un attaccante con write può riscrivere la catena e la testa e
 * passare comunque. L'unico artefatto non forgiabile è il checkpoint firmato ES256. Perciò qui,
 * oltre alla consistenza interna, ancoriamo la verifica al checkpoint firmato più alto: ne validiamo
 * la firma (via TokenSigner/JWKS) e confrontiamo l'hash RICALCOLATO al suo `up_to_seq` con l'`head_hash`
 * firmato. Fail-closed. Un attaccante che riscrive la catura sotto il checkpoint viene smascherato dal
 * mismatch; un troncamento sotto il checkpoint dal fatto che la catena è più corta del seq firmato.
 */
final class AuditChainVerifier
{
    public function __construct(
        private readonly AuditHasher $hasher,
        private readonly AuditCheckpointer $checkpointer,
    ) {}

    public function verify(string $stream): AuditVerificationResult
    {
        // Il checkpoint firmato più alto è l'ancora di fiducia (indipendente dal DB scrivibile).
        $checkpoint = AuditCheckpoint::query()
            ->where('stream', $stream)
            ->orderByDesc('up_to_seq')
            ->first();

        if ($checkpoint !== null) {
            // Firma non valida/manomessa/scaduta → fail-closed subito: l'ancora non è affidabile.
            $checkpointResult = $this->checkpointer->verify($checkpoint);
            if (!$checkpointResult->valid) {
                return $checkpointResult;
            }
        }

        $prevHash = AuditHasher::GENESIS;
        $expectedSeq = 1;
        $checked = 0;
        $hashAtCheckpoint = null;

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

            // IAM-07: cattura l'hash ricalcolato ESATTAMENTE al seq firmato dal checkpoint.
            if ($checkpoint !== null && $event->seq === $checkpoint->up_to_seq) {
                $hashAtCheckpoint = (string) $event->hash;
            }

            $prevHash = $event->hash;
            $expectedSeq++;
        }

        // IAM-07: ancoraggio al checkpoint firmato. La catena DEVE arrivare almeno fino al seq firmato
        // (un troncamento sotto il checkpoint = catena più corta del seq ancorato) e l'hash ricalcolato
        // a quel seq DEVE combaciare con l'head_hash firmato (una riscrittura sotto il checkpoint cambia
        // l'hash). Nessuno dei due dipende dalla testa scrivibile.
        if ($checkpoint !== null) {
            if ($hashAtCheckpoint === null) {
                return AuditVerificationResult::broken($checked, null, "catena troncata sotto il checkpoint firmato (seq {$checkpoint->up_to_seq} assente)", 'tail_truncated');
            }
            if (!hash_equals($hashAtCheckpoint, $checkpoint->head_hash)) {
                return AuditVerificationResult::broken($checked, null, 'hash ricalcolato al checkpoint diverso dall\'head_hash firmato (catena riscritta sotto il checkpoint)', 'tampered');
            }
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

        // `anchored` è vero solo se un checkpoint firmato valido ha ancorato la testa; altrimenti la
        // catena è internamente coerente ma non ancorata (segnale onesto per l'auditor).
        return AuditVerificationResult::ok($checked, anchored: $checkpoint !== null);
    }
}
