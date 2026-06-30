<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Governance\Requests\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;

/**
 * Step di una catena di approvazione (doc 19 §9). AND sequenziale: lo step k+1 si attiva solo quando k
 * è approvato. `status`, `decided_by/at`, `note` NON sono mass-assignable: li scrive solo
 * l'ApproverChainService → niente auto-decisione via mass-assignment (mirror di AccessRequest/Grant).
 *
 * @property string $id
 * @property string $access_request_id
 * @property int $position
 * @property string $approver_type
 * @property string $approver_ref
 * @property string $status
 * @property string|null $decided_by
 * @property Carbon|null $decided_at
 * @property string|null $note
 */
final class ApprovalStep extends Model
{
    use HasUlids;

    protected $table = 'iam_approval_steps';

    /** @var list<string> status, decided_by/at e note fuori da fillable: li scrive solo l'ApproverChainService. */
    protected $fillable = ['access_request_id', 'position', 'approver_type', 'approver_ref'];

    /** @var array<string, mixed> */
    protected $attributes = [
        'status' => 'pending',
    ];

    protected $casts = [
        'position' => 'integer',
        'decided_at' => 'datetime',
    ];

    /** @return BelongsTo<AccessRequest, $this> */
    public function accessRequest(): BelongsTo
    {
        return $this->belongsTo(AccessRequest::class, 'access_request_id');
    }
}
