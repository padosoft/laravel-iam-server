<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\OAuth\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;

/**
 * Scope OAuth/OIDC (doc 13 §4). Catalogo: scope OIDC standard + scope dichiarati dai manifest.
 *
 * @property string $id
 * @property string $identifier
 * @property string|null $description
 */
final class OauthScope extends Model
{
    use HasUlids;

    protected $table = 'iam_oauth_scopes';

    /** @var list<string> */
    protected $fillable = ['identifier', 'description'];
}
