<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\OAuth\Models;

use Illuminate\Database\Eloquent\Model;

/**
 * Stato di una catena di refresh token (famiglia di rotazione). `compromised=true` quando un
 * replay è stato rilevato: da quel momento OGNI token della catena è invalido, anche quelli
 * emessi concorrentemente dopo la rilevazione (RFC 9700 §4.14.2).
 *
 * @property string $chain_id
 * @property bool $compromised
 */
final class OauthTokenChain extends Model
{
    protected $table = 'iam_oauth_token_chains';

    protected $primaryKey = 'chain_id';

    public $incrementing = false;

    protected $keyType = 'string';

    /** @var list<string> */
    protected $fillable = ['chain_id', 'compromised'];

    /** @var array<string, mixed> */
    protected $attributes = ['compromised' => false];

    protected $casts = ['compromised' => 'boolean'];
}
