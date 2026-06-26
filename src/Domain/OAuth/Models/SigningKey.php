<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\OAuth\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;

/**
 * Chiave di firma JWT (EC P-256). Privata incartata; pubblica nel JWKS (doc 13 §8).
 *
 * @property string $id
 * @property string $kid
 * @property string $alg
 * @property array<string, mixed> $public_jwk
 * @property string $public_pem
 * @property string $private_wrapped
 * @property string $status
 */
final class SigningKey extends Model
{
    use HasUlids;

    protected $table = 'iam_signing_keys';

    /** @var list<string> */
    protected $fillable = [
        'kid', 'alg', 'public_jwk', 'public_pem', 'private_wrapped', 'status', 'rotated_at', 'revoked_at',
    ];

    /** @var array<string, mixed> */
    protected $attributes = [
        'alg' => 'ES256',
        'status' => 'active',
    ];

    protected $casts = [
        'public_jwk' => 'array',
        'rotated_at' => 'datetime',
        'revoked_at' => 'datetime',
    ];

    /** @var list<string> Mai serializzare la chiave privata (anche se incartata). */
    protected $hidden = ['private_wrapped'];
}
