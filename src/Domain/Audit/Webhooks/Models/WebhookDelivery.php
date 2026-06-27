<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Audit\Webhooks\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * Log di consegna di un webhook (doc 12 §6) — audit della consegna stessa. Unico per
 * (subscription, event_uuid) → idempotenza. `status`: pending|sending|delivered|retrying|failed (DLQ).
 * `sending` è lo stato transitorio del claim atomico (un crash mid-send è recuperato dal retrier).
 *
 * @property string $id
 * @property string $subscription_id
 * @property string $event_uuid
 * @property int $attempt
 * @property string $status
 * @property int|null $response_code
 * @property string|null $response_excerpt
 * @property string|null $signature
 * @property Carbon|null $next_retry_at
 * @property Carbon|null $delivered_at
 */
final class WebhookDelivery extends Model
{
    use HasUlids;

    protected $table = 'iam_webhook_deliveries';

    protected $fillable = [
        'subscription_id', 'event_uuid', 'attempt', 'status', 'response_code',
        'response_excerpt', 'signature', 'next_retry_at', 'delivered_at',
    ];

    /** @var array<string, mixed> */
    protected $attributes = [
        'status' => 'pending',
        'attempt' => 0,
    ];

    protected $casts = [
        'attempt' => 'integer',
        'response_code' => 'integer',
        'next_retry_at' => 'datetime',
        'delivered_at' => 'datetime',
    ];
}
