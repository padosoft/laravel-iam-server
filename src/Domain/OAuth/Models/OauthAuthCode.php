<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\OAuth\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * Authorization code emesso da /oauth/authorize (doc 13 §6). Single-use, breve durata.
 *
 * @property string $id
 * @property string $auth_code_id
 * @property string $client_id
 * @property string|null $user_id
 * @property list<string>|null $scopes
 * @property bool $revoked
 * @property Carbon|null $expires_at
 */
final class OauthAuthCode extends Model
{
    use HasUlids;

    protected $table = 'iam_oauth_auth_codes';

    /** @var list<string> */
    protected $fillable = ['auth_code_id', 'client_id', 'user_id', 'scopes', 'revoked', 'expires_at'];

    /** @var array<string, mixed> */
    protected $attributes = ['revoked' => false];

    protected $casts = [
        'scopes' => 'array',
        'revoked' => 'boolean',
        'expires_at' => 'datetime',
    ];
}
