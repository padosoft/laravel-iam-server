<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Audit\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * Evento di audit tamper-evident (doc 12 §3). I campi della catena (seq/prev_hash/hash/sealed_at)
 * NON sono fillable: li scrive solo l'AuditChainAppender sotto lock sulla testa dello stream. Il
 * resto descrive l'evento (chi/cosa/quando) ed entra nel payload canonico hashato.
 *
 * @property string $uuid
 * @property string $stream
 * @property int $seq
 * @property Carbon $occurred_at
 * @property string|null $actor_user_id
 * @property string|null $actor_client_id
 * @property string|null $actor_agent_id
 * @property string|null $actor_assurance
 * @property string|null $target_type
 * @property string|null $target_id
 * @property string|null $organization_id
 * @property string|null $application_id
 * @property string $event_type
 * @property string $risk_level
 * @property string|null $ip_hash
 * @property string|null $user_agent_hash
 * @property string|null $correlation_id
 * @property array<string, mixed>|null $before_json
 * @property array<string, mixed>|null $after_json
 * @property string|null $pii_dek_id
 * @property array<string, mixed>|null $metadata_json
 * @property string $prev_hash
 * @property string $hash
 * @property Carbon|null $sealed_at
 */
final class AuditEvent extends Model
{
    use HasUlids;

    protected $table = 'iam_audit_events';

    protected $primaryKey = 'uuid';

    /** @var list<string> Campi descrittivi dell'evento; la catena (seq/prev_hash/hash) è gestita dall'appender. */
    protected $fillable = [
        'stream', 'occurred_at', 'actor_user_id', 'actor_client_id', 'actor_agent_id', 'actor_assurance',
        'target_type', 'target_id', 'organization_id', 'application_id', 'event_type', 'risk_level',
        'ip_hash', 'user_agent_hash', 'correlation_id', 'before_json', 'after_json', 'pii_dek_id', 'metadata_json',
    ];

    /** @var array<string, mixed> */
    protected $attributes = [
        'risk_level' => 'low',
    ];

    protected $casts = [
        'occurred_at' => 'datetime',
        'sealed_at' => 'datetime',
        'seq' => 'integer',
        'before_json' => 'array',
        'after_json' => 'array',
        'metadata_json' => 'array',
    ];

    /** @return list<string> */
    public function uniqueIds(): array
    {
        return ['uuid'];
    }

    /**
     * Rappresentazione DETERMINISTICA dei campi coperti dall'hash (tutto tranne i campi della catena
     * stessa: prev_hash/hash/sealed_at e i timestamp gestiti dal DB). L'ordine non conta: l'hasher
     * canonicalizza con ksort ricorsivo. `occurred_at` come ISO-8601 UTC per riproducibilità.
     *
     * @return array<string, mixed>
     */
    public function canonicalPayload(): array
    {
        return [
            'uuid' => $this->uuid,
            'stream' => $this->stream,
            'seq' => $this->seq,
            'occurred_at' => $this->occurred_at->utc()->format('Y-m-d\TH:i:s.u\Z'),
            'actor_user_id' => $this->actor_user_id,
            'actor_client_id' => $this->actor_client_id,
            'actor_agent_id' => $this->actor_agent_id,
            'actor_assurance' => $this->actor_assurance,
            'target_type' => $this->target_type,
            'target_id' => $this->target_id,
            'organization_id' => $this->organization_id,
            'application_id' => $this->application_id,
            'event_type' => $this->event_type,
            'risk_level' => $this->risk_level,
            'ip_hash' => $this->ip_hash,
            'user_agent_hash' => $this->user_agent_hash,
            'correlation_id' => $this->correlation_id,
            'before_json' => $this->before_json,
            'after_json' => $this->after_json,
            'pii_dek_id' => $this->pii_dek_id,
            'metadata_json' => $this->metadata_json,
        ];
    }
}
