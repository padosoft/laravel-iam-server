<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Identity\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * Sessione server-side (doc 10 §3). `id` = sid. Revocabile; idle + absolute timeout.
 * Campi di lifecycle (revoked/step_up) fuori da fillable: valorizzati via metodi controllati.
 *
 * @property string $id
 * @property string $user_id
 * @property string|null $organization_id
 * @property string $aal
 * @property int $idle_timeout
 * @property Carbon $last_activity_at
 * @property Carbon $absolute_expires_at
 * @property Carbon|null $step_up_at
 * @property Carbon|null $revoked_at
 * @property string|null $revoked_reason
 * @property Carbon|null $created_at
 */
final class Session extends Model
{
    use HasUlids;

    protected $table = 'iam_sessions';

    /**
     * @var list<string> last_activity_at/absolute_expires_at sono FUORI da fillable: i timeout
     *                   (specie l'absolute, mai estendibile) li scrive solo il registry via forceFill.
     */
    protected $fillable = [
        'user_id', 'organization_id', 'aal', 'idle_timeout',
        'device_fingerprint_hash', 'ip_hash', 'user_agent_hash',
    ];

    /** @var array<string, mixed> */
    protected $attributes = ['aal' => 'aal1'];

    protected $casts = [
        'last_activity_at' => 'datetime',
        'absolute_expires_at' => 'datetime',
        'step_up_at' => 'datetime',
        'revoked_at' => 'datetime',
    ];

    public function markRevoked(string $reason): void
    {
        if ($this->revoked_at !== null) {
            return; // idempotente
        }
        $this->forceFill(['revoked_at' => now(), 'revoked_reason' => $reason !== '' ? $reason : 'revoked'])->save();
    }

    /** Eleva l'AAL della sessione e registra l'istante di step-up. */
    public function recordStepUp(string $aal): void
    {
        $this->forceFill(['aal' => $aal, 'step_up_at' => now()])->save();
    }
}
