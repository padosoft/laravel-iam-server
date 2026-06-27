<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Governance\Requests\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * Richiesta di accesso self-service (doc 14 §4). Un utente richiede un ruolo `self_requestable`;
 * la richiesta segue il workflow di approvazione e, se approvata, materializza un grant time-boxed
 * (source=access_request). status, decided_at/by e granted_grant_id NON sono mass-assignable: li
 * scrive solo l'AccessRequestService → niente auto-approvazione via mass-assignment.
 *
 * @property string $id
 * @property string|null $organization_id
 * @property string $requester_type
 * @property string $requester_id
 * @property string $application_key
 * @property string $role_key
 * @property string|null $justification
 * @property string $status
 * @property array<array-key, mixed>|null $approver_chain_json
 * @property array<array-key, mixed>|null $request_policy_json
 * @property Carbon|null $decided_at
 * @property string|null $decided_by
 * @property string|null $granted_grant_id
 */
final class AccessRequest extends Model
{
    use HasUlids;

    protected $table = 'iam_access_requests';

    /** @var list<string> */
    protected $fillable = [
        'organization_id', 'requester_type', 'requester_id',
        'application_key', 'role_key', 'justification', 'approver_chain_json', 'request_policy_json',
        // status, decided_at/by, decision_note, granted_grant_id NON fillable: li scrive solo il service.
    ];

    /** @var array<string, mixed> */
    protected $attributes = [
        'requester_type' => 'user',
        'status' => 'pending',
    ];

    protected $casts = [
        'approver_chain_json' => 'array',
        'request_policy_json' => 'array',
        'decided_at' => 'datetime',
    ];
}
