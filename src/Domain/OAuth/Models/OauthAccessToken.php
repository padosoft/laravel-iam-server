<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\OAuth\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * Ledger dei token emessi (doc 13 §5): supporta introspection e revoca immediata
 * (fail-closed) anche per gli access token JWT, identificati dal loro jti.
 *
 * @property string $id
 * @property string $jti
 * @property string $client_id
 * @property string|null $user_id
 * @property list<string>|null $scopes
 * @property bool $revoked
 * @property Carbon|null $expires_at
 */
final class OauthAccessToken extends Model
{
    use HasUlids;

    protected $table = 'iam_oauth_access_tokens';

    /** @var list<string> */
    protected $fillable = ['jti', 'client_id', 'user_id', 'scopes', 'revoked', 'expires_at'];

    /** @var array<string, mixed> */
    protected $attributes = [
        'revoked' => false,
    ];

    protected $casts = [
        'scopes' => 'array',
        'revoked' => 'boolean',
        'expires_at' => 'datetime',
    ];
}
