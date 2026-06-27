<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Audit\Webhooks\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;

/**
 * Subscription webhook per-org (doc 12 §6). `secret_encrypted` è l'envelope SecretCipher del
 * segreto HMAC; `event_filters` è la lista di pattern (es. "grant.*") che l'evento deve matchare.
 *
 * @property string $id
 * @property string|null $organization_id
 * @property string $url
 * @property array{ciphertext: string, wrapped_dek: string|null, key_id: string, key_version: int, scope: string|null} $secret_encrypted
 * @property list<string> $event_filters
 * @property string $status
 */
final class WebhookSubscription extends Model
{
    use HasUlids;

    protected $table = 'iam_webhook_subscriptions';

    protected $fillable = ['organization_id', 'url', 'secret_encrypted', 'event_filters', 'status'];

    /** @var array<string, mixed> */
    protected $attributes = [
        'status' => 'active',
    ];

    protected $casts = [
        'secret_encrypted' => 'array',
        'event_filters' => 'array',
    ];
}
