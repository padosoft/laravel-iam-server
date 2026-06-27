<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Audit\Outbox;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * Messaggio dell'outbox transazionale (doc 12 §5). `payload_json` contiene gli attributi
 * dell'evento di audit da sigillare. `status` evita la doppia consegna.
 *
 * @property string $id
 * @property string $event_type
 * @property string $stream
 * @property array<string, mixed> $payload_json
 * @property string $status
 * @property int $attempts
 * @property string|null $last_error
 * @property string|null $audit_uuid
 * @property Carbon $created_at
 * @property Carbon|null $delivered_at
 */
final class OutboxMessage extends Model
{
    use HasUlids;

    protected $table = 'iam_outbox';

    public $timestamps = false;

    protected $fillable = ['event_type', 'stream', 'payload_json', 'created_at'];

    /** @var array<string, mixed> */
    protected $attributes = [
        'status' => 'pending',
        'attempts' => 0,
    ];

    protected $casts = [
        'payload_json' => 'array',
        'attempts' => 'integer',
        'created_at' => 'datetime',
        'delivered_at' => 'datetime',
    ];
}
