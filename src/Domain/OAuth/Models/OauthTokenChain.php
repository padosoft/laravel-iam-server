<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\OAuth\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * Stato di una catena di refresh token (famiglia di rotazione). `compromised=true` quando un
 * replay è stato rilevato: da quel momento OGNI token della catena è invalido, anche quelli
 * emessi concorrentemente dopo la rilevazione (RFC 9700 §4.14.2). `auth_time` è l'istante di
 * autenticazione originale, propagato agli id_token dei refresh (OIDC Core §12.2).
 *
 * @property string $chain_id
 * @property bool $compromised
 * @property Carbon|null $auth_time
 */
final class OauthTokenChain extends Model
{
    protected $table = 'iam_oauth_token_chains';

    protected $primaryKey = 'chain_id';

    public $incrementing = false;

    protected $keyType = 'string';

    /** @var list<string> */
    protected $fillable = ['chain_id', 'compromised', 'auth_time'];

    /** @var array<string, mixed> */
    protected $attributes = ['compromised' => false];

    protected $casts = ['compromised' => 'boolean', 'auth_time' => 'datetime'];
}
