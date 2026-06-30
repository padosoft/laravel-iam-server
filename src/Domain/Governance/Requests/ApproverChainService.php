<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Governance\Requests;

use Illuminate\Support\Facades\DB;
use Padosoft\Iam\Domain\Audit\Pii\AuditRecorder;
use Padosoft\Iam\Domain\Authorization\Models\Grant;
use Padosoft\Iam\Domain\Governance\Requests\Models\AccessRequest;
use Padosoft\Iam\Domain\Governance\Requests\Models\ApprovalStep;

/**
 * Catena di approvazione multi-step per Access Request (doc 19 §9). AND sequenziale: lo step k+1 si
 * attiva solo quando k è `approved`; un reject su qualunque step → request `rejected` (fail-closed). Il
 * grant time-boxed nasce SOLO all'ultimo step, delegando a AccessRequestService::finalizeApproval()
 * (l'unico materializzatore di grant): l'invariante M8 è quindi preservata anche con N approver.
 */
final class ApproverChainService
{
    public function __construct(
        private readonly AccessRequestService $requests,
        private readonly ?AuditRecorder $audit = null,
    ) {}

    /**
     * Approva uno step. Ritorna il Grant se era l'ULTIMO step (catena completata), altrimenti null
     * (la richiesta resta `pending` e si attiva lo step successivo). Atomico (lock su request + step).
     */
    public function approveStep(AccessRequest $req, ApprovalStep $step, string $approver): ?Grant
    {
        // SoD: un approver di step non può essere il richiedente (coerente con l'approvazione singola).
        $this->requests->assertNotSelfApproval($req, $approver);

        return DB::transaction(function () use ($req, $step, $approver): ?Grant {
            $lockedReq = AccessRequest::query()->whereKey($req->id)->lockForUpdate()->first();
            if ($lockedReq === null || $lockedReq->status !== 'pending') {
                throw new \RuntimeException("Richiesta {$req->id} non più pending.");
            }

            $lockedStep = ApprovalStep::query()->whereKey($step->id)->lockForUpdate()->first();
            if ($lockedStep === null || $lockedStep->access_request_id !== $lockedReq->id) {
                throw new \RuntimeException('Step non appartenente alla richiesta.');
            }
            if ($lockedStep->status !== 'pending') {
                throw new \RuntimeException("Step {$step->id} già deciso.");
            }

            // AND sequenziale: si può approvare solo lo step ATTIVO (il pending con la posizione minima).
            $active = ApprovalStep::query()
                ->where('access_request_id', $lockedReq->id)
                ->where('status', 'pending')
                ->orderBy('position')
                ->first();
            if ($active === null || $active->id !== $lockedStep->id) {
                throw new \RuntimeException('Step non ancora attivo: rispetta l\'ordine della catena.');
            }

            $lockedStep->forceFill([
                'status' => 'approved',
                'decided_by' => $approver,
                'decided_at' => now(),
            ])->save();

            $this->record('iam.access_request.step_approved', $lockedReq, [
                'position' => $lockedStep->position, 'approver' => $approver,
            ]);

            // Restano step pending? Se sì, la catena prosegue (nessun grant ancora). Se no → ultimo step:
            // delega a finalizeApproval() (unico materializzatore di grant) sotto la stessa transazione.
            $remaining = ApprovalStep::query()
                ->where('access_request_id', $lockedReq->id)
                ->where('status', 'pending')
                ->count();
            if ($remaining > 0) {
                return null;
            }

            return $this->requests->finalizeApproval($lockedReq, $approver);
        });
    }

    /**
     * Rifiuta uno step → l'INTERA richiesta è `rejected` (fail-closed), nessun grant emesso. Idempotente
     * sullo stato della richiesta.
     */
    public function rejectStep(AccessRequest $req, ApprovalStep $step, string $approver, ?string $note = null): void
    {
        DB::transaction(function () use ($req, $step, $approver, $note): void {
            $lockedReq = AccessRequest::query()->whereKey($req->id)->lockForUpdate()->first();
            if ($lockedReq === null || $lockedReq->status !== 'pending') {
                throw new \RuntimeException("Richiesta {$req->id} non più pending.");
            }

            $lockedStep = ApprovalStep::query()->whereKey($step->id)->lockForUpdate()->first();
            if ($lockedStep === null || $lockedStep->access_request_id !== $lockedReq->id) {
                throw new \RuntimeException('Step non appartenente alla richiesta.');
            }
            if ($lockedStep->status !== 'pending') {
                throw new \RuntimeException("Step {$step->id} già deciso.");
            }

            $lockedStep->forceFill([
                'status' => 'rejected',
                'decided_by' => $approver,
                'decided_at' => now(),
                'note' => $note,
            ])->save();

            // La richiesta è rifiutata fail-closed (un solo reject basta). Niente grant.
            $lockedReq->forceFill([
                'status' => 'rejected',
                'decided_at' => now(),
                'decided_by' => $approver,
                'decision_note' => $note,
            ])->save();

            $this->record('iam.access_request.step_rejected', $lockedReq, [
                'position' => $lockedStep->position, 'approver' => $approver,
            ]);
            $this->record('iam.access_request.rejected', $lockedReq, ['approver' => $approver]);
        });
    }

    /**
     * @param  array<string, mixed>  $metadata
     */
    private function record(string $eventType, AccessRequest $req, array $metadata): void
    {
        ($this->audit ?? app(AuditRecorder::class))->record([
            'stream' => 'governance',
            'event_type' => $eventType,
            'target_type' => 'access_request',
            'target_id' => $req->id,
            'organization_id' => $req->organization_id,
            'application_id' => $req->application_key,
            'metadata_json' => $metadata,
        ]);
    }
}
