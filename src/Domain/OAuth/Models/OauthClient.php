<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\OAuth\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Hash;

/**
 * Client OAuth (doc 13 §4). In v1 tabella minimale; in M6 di proprietà
 * dell'Application Registry manifest-driven.
 *
 * @property string $id
 * @property string $client_id
 * @property string $name
 * @property string|null $secret
 * @property list<string>|null $redirect_uris
 * @property list<string> $grants
 * @property list<string>|null $scopes
 * @property bool $is_confidential
 * @property bool $is_first_party
 * @property string|null $organization_id
 * @property string|null $application_key
 * @property Carbon|null $revoked_at
 */
final class OauthClient extends Model
{
    use HasUlids;

    protected $table = 'iam_oauth_clients';

    /** @var list<string> secret e revoked_at sono fuori da fillable: valorizzati via metodi controllati. */
    protected $fillable = [
        'client_id', 'name', 'redirect_uris', 'grants', 'scopes',
        'is_confidential', 'is_first_party', 'organization_id', 'application_key',
    ];

    /** @var array<string, mixed> */
    protected $attributes = [
        'is_confidential' => true,
        'is_first_party' => true,
    ];

    protected $casts = [
        'redirect_uris' => 'array',
        'grants' => 'array',
        'scopes' => 'array',
        'is_confidential' => 'boolean',
        'is_first_party' => 'boolean',
        'revoked_at' => 'datetime',
    ];

    /** @var list<string> Il secret (hash) non va mai serializzato. */
    protected $hidden = ['secret'];

    /**
     * Registra un client; il secret (se confidential) è passato in chiaro e custodito come hash.
     * Il secret resta fuori da fillable per evitare mass-assignment accidentale.
     *
     * @param  array<string, mixed>  $attributes
     */
    public static function register(array $attributes, ?string $plainSecret = null): self
    {
        $client = new self;
        $client->fill($attributes);
        if ($plainSecret !== null && $plainSecret !== '') {
            $client->secret = Hash::make($plainSecret);
        }
        $client->save();

        return $client;
    }

    public function revoke(): void
    {
        $this->revoked_at = now();
        $this->save();
    }
}
