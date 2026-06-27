<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Governance\Requests;

use Illuminate\Support\Facades\DB;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Iam\Domain\Audit\Pii\AuditRecorder;
use Padosoft\Iam\Domain\Authorization\Models\Grant;
use Padosoft\Iam\Domain\Authorization\Models\Role;
use Padosoft\Iam\Domain\Governance\Requests\Models\AccessRequest;

/**
 * Workflow Access Request self-service (doc 14 §4): submit → approve|reject|cancel. La submit passa
 * dal RequestCatalog (default-deny: non si può richiedere ciò che non si potrebbe vedere). L'approve
 * materializza un grant TIME-BOXED (source=access_request, valid_until da max_duration) e audita.
 * status/decided_* del request e i campi di provenienza del grant non sono mass-assignable.
 */
final class AccessRequestService
{
    public function __construct(
        private readonly RequestCatalog $catalog,
        private readonly ?AuditRecorder $audit = null,
    ) {}

    /**
     * Crea una richiesta `pending`. Fail-closed: rifiuta se il ruolo non è richiedibile dal soggetto
     * (gate del catalogo) o se manca la giustificazione quando il manifest la richiede.
     */
    public function submit(SubjectRef $requester, string $roleFullKey, ?string $justification = null, ?string $organizationId = null): AccessRequest
    {
        $role = Role::query()->where('full_key', $roleFullKey)->whereNull('deprecated_at')->first();

        // STESSO messaggio sia per "il ruolo non esiste" sia per "non puoi richiederlo": un richiedente
        // non deve poter distinguere i due casi, altrimenti enumererebbe il catalogo (privacy doc 14 §4).
        if ($role === null || !$this->catalog->canRequest($role, $requester, $organizationId)) {
            throw new \RuntimeException("Ruolo \"{$roleFullKey}\" non richiedibile.");
        }

        $request = $role->request_json ?? [];
        if (($request['requires_justification'] ?? false) === true && ($justification === null || trim($justification) === '')) {
            throw new \InvalidArgumentException('Giustificazione obbligatoria per questo ruolo.');
        }

        // Niente richieste pending duplicate per lo stesso (richiedente, ruolo, org): evita flood degli
        // approver e ambiguità nell'audit. Una richiesta già decisa non blocca una nuova richiesta.
        $duplicate = AccessRequest::query()
            ->where('requester_type', $requester->type)
            ->where('requester_id', $requester->id)
            ->where('role_key', $role->full_key)
            ->where('status', 'pending')
            ->when($organizationId !== null, fn ($q) => $q->where('organization_id', $organizationId), fn ($q) => $q->whereNull('organization_id'))
            ->exists();
        if ($duplicate) {
            throw new \RuntimeException("Esiste già una richiesta pendente per \"{$roleFullKey}\".");
        }

        $accessRequest = AccessRequest::create([
            'organization_id' => $organizationId,
            'requester_type' => $requester->type,
            'requester_id' => $requester->id,
            'application_key' => (string) $role->app_key,
            'role_key' => $role->full_key,
            'justification' => $justification,
            'approver_chain_json' => $this->approvers($request),
            // Snapshot della policy (max_duration/...) → l'approvazione non dipende dal ruolo vivo.
            'request_policy_json' => $request,
        ]);

        $this->record('iam.access_request.submitted', $accessRequest, [
            'role_key' => $role->full_key,
            'requester' => (string) $requester,
        ]);

        return $accessRequest;
    }

    /**
     * Approva la richiesta: crea il grant time-boxed e lo collega. Atomico (transazione) e
     * idempotente sullo stato: solo una richiesta `pending` è approvabile.
     */
    public function approve(AccessRequest $req, string $approver): Grant
    {
        // Segregation of duties: un richiedente non può approvare la propria richiesta. L'autorizzazione
        // dell'approver rispetto alla approver_chain (ruoli/owner) è applicata a monte dall'API (M10).
        if ($approver === (string) new SubjectRef($req->requester_type, $req->requester_id)) {
            throw new \RuntimeException('Self-approval non consentita: l\'approver non può essere il richiedente.');
        }

        return DB::transaction(function () use ($req, $approver): Grant {
            $locked = AccessRequest::query()->whereKey($req->id)->lockForUpdate()->first();
            if ($locked === null || $locked->status !== 'pending') {
                throw new \RuntimeException("Richiesta {$req->id} non più pending.");
            }

            // La durata viene dallo SNAPSHOT congelato alla submit, non dal ruolo (che potrebbe non
            // esistere più o essere stato modificato) → grant sempre time-boxed come pattuito.
            $policy = is_array($locked->request_policy_json) ? $locked->request_policy_json : [];
            $validUntil = $this->expiry($policy);

            // Se il soggetto possiede già un grant equivalente attivo, una seconda concessione
            // collide sull'identity_hash (unique): la intercettiamo come errore di dominio chiaro
            // invece di lasciar emergere una QueryException (no 500/DoS sul workflow).
            $existing = Grant::query()->active()
                ->where('subject_type', $locked->requester_type)
                ->where('subject_id', $locked->requester_id)
                ->where('privilege_type', 'role')
                ->where('privilege_key', $locked->role_key)
                ->where('effect', 'permit')
                ->when($locked->organization_id !== null,
                    fn ($q) => $q->where('organization_id', $locked->organization_id),
                    fn ($q) => $q->whereNull('organization_id'))
                ->when($locked->application_key !== '',
                    fn ($q) => $q->where('application_key', $locked->application_key))
                ->exists();
            if ($existing) {
                throw new \RuntimeException("Il soggetto possiede già un accesso attivo per \"{$locked->role_key}\".");
            }

            $grant = Grant::create([
                'organization_id' => $locked->organization_id,
                'application_key' => $locked->application_key,
                'subject_type' => $locked->requester_type,
                'subject_id' => $locked->requester_id,
                'privilege_type' => 'role',
                'privilege_key' => $locked->role_key,
                'effect' => 'permit',
                'source' => 'access_request',
                'justification' => $locked->justification,
                'approval_ref' => $locked->id,
                'valid_from' => now(),
                'valid_until' => $validUntil,
                'created_by' => $approver,
            ]);

            $locked->forceFill([
                'status' => 'approved',
                'decided_at' => now(),
                'decided_by' => $approver,
                'granted_grant_id' => $grant->id,
            ])->save();

            $this->record('iam.access_request.approved', $locked, [
                'grant_id' => $grant->id,
                'valid_until' => $grant->valid_until?->toIso8601String(),
                'approver' => $approver,
            ]);

            return $grant;
        });
    }

    public function reject(AccessRequest $req, string $approver, ?string $note = null): void
    {
        DB::transaction(function () use ($req, $approver, $note): void {
            $locked = AccessRequest::query()->whereKey($req->id)->lockForUpdate()->first();
            if ($locked === null || $locked->status !== 'pending') {
                throw new \RuntimeException("Richiesta {$req->id} non più pending.");
            }
            $locked->forceFill([
                'status' => 'rejected',
                'decided_at' => now(),
                'decided_by' => $approver,
                'decision_note' => $note,
            ])->save();

            $this->record('iam.access_request.rejected', $locked, ['approver' => $approver]);
        });
        $req->refresh();
    }

    /** Annullamento da parte del richiedente (solo se ancora pending). */
    public function cancel(AccessRequest $req, SubjectRef $requester): void
    {
        // L'identità del richiedente si verifica fuori dal lock (non cambia), ma la transizione di stato
        // va sotto lock + ricontrollo pending, così un cancel concorrente a un approve non sovrascrive
        // un'approvazione lasciando un grant orfano attivo (TOCTOU).
        if ($req->requester_type !== $requester->type || $req->requester_id !== $requester->id) {
            throw new \RuntimeException('Solo il richiedente può annullare la propria richiesta.');
        }

        DB::transaction(function () use ($req, $requester): void {
            $locked = AccessRequest::query()->whereKey($req->id)->lockForUpdate()->first();
            if ($locked === null || $locked->status !== 'pending') {
                throw new \RuntimeException("Richiesta {$req->id} non più pending.");
            }
            $locked->forceFill([
                'status' => 'cancelled',
                'decided_at' => now(),
                'decided_by' => (string) $requester,
            ])->save();

            $this->record('iam.access_request.cancelled', $locked, ['by' => (string) $requester]);
        });
        $req->refresh();
    }

    /**
     * Scadenza del grant da `max_duration` (ISO-8601, es. P30D). Assente/non valida → grant permanente
     * (valid_until null): la durata è opzionale, ma una stringa malformata non deve bloccare l'approvazione.
     *
     * @param  array<array-key, mixed>  $request
     */
    private function expiry(array $request): ?\DateTimeInterface
    {
        $duration = $request['max_duration'] ?? null;
        // Assente: durata illimitata = scelta esplicita (grant permanente). Presente ma malformata o
        // degenere: NON si degrada a permanente in silenzio (sarebbe un'escalation da typo) → si blocca.
        if ($duration === null || $duration === '') {
            return null;
        }
        if (!is_string($duration)) {
            throw new \InvalidArgumentException('max_duration non valida.');
        }
        try {
            $expiry = now()->add(new \DateInterval($duration));
        } catch (\Throwable) {
            throw new \InvalidArgumentException("max_duration \"{$duration}\" non è una durata ISO-8601 valida.");
        }
        if ($expiry->lessThanOrEqualTo(now())) {
            throw new \InvalidArgumentException("max_duration \"{$duration}\" produce un grant già scaduto.");
        }

        return $expiry;
    }

    /**
     * @param  array<array-key, mixed>  $request
     * @return list<string>
     */
    private function approvers(array $request): array
    {
        $approvers = $request['approvers'] ?? null;
        if (!is_array($approvers)) {
            return [];
        }

        return array_values(array_filter($approvers, static fn ($a): bool => is_string($a) && $a !== ''));
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
