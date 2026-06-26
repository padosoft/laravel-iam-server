<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\OAuth\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * Refresh token (doc 13 §6). In M4b.3 supporta la rotation con replay detection
 * (refresh riusato → revoca dell'intera catena).
 *
 * @property string $id
 * @property string $refresh_token_id
 * @property string $access_token_jti
 * @property bool $revoked
 * @property Carbon|null $expires_at
 */
final class OauthRefreshToken extends Model
{
    use HasUlids;

    protected $table = 'iam_oauth_refresh_tokens';

    /** @var list<string> */
    protected $fillable = ['refresh_token_id', 'access_token_jti', 'revoked', 'expires_at'];

    /** @var array<string, mixed> */
    protected $attributes = ['revoked' => false];

    protected $casts = [
        'revoked' => 'boolean',
        'expires_at' => 'datetime',
    ];
}
