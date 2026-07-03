<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\OAuth\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;

/**
 * Client OAuth (doc 13 §4). In v1 tabella minimale; in M6 di proprietà
 * dell'Application Registry manifest-driven.
 *
 * @property string $id
 * @property string $client_id
 * @property string $name
 * @property string|null $secret
 * @property Carbon|null $secret_expires_at
 * @property string|null $secret_previous
 * @property Carbon|null $secret_previous_expires_at
 * @property Carbon|null $secret_rotated_at
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

    /** @var array<string, mixed> Secure-by-default: third-party (consenso esplicito) salvo marcatura. */
    protected $attributes = [
        'is_confidential' => true,
        'is_first_party' => false,
    ];

    protected $casts = [
        'redirect_uris' => 'array',
        'grants' => 'array',
        'scopes' => 'array',
        'is_confidential' => 'boolean',
        'is_first_party' => 'boolean',
        'revoked_at' => 'datetime',
        'secret_expires_at' => 'datetime',
        'secret_previous_expires_at' => 'datetime',
        'secret_rotated_at' => 'datetime',
    ];

    /** @var list<string> Gli hash dei secret (corrente + precedente) non vanno mai serializzati. */
    protected $hidden = ['secret', 'secret_previous'];

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

    /**
     * Ruota il secret con rollover a ZERO downtime: il secret corrente diventa `secret_previous`,
     * valido per `graceSeconds`; ne viene emesso uno nuovo (che scade dopo `ttlSeconds`, o mai se null).
     * Ritorna il nuovo secret IN CHIARO — da consegnare/mostrare UNA sola volta (non è mai persistito
     * in chiaro). Solo per client confidential.
     */
    public function rotateSecret(int $graceSeconds, ?int $ttlSeconds): string
    {
        $now = now();
        if (is_string($this->secret) && $this->secret !== '') {
            $this->secret_previous = $this->secret;
            $this->secret_previous_expires_at = $now->copy()->addSeconds(max(0, $graceSeconds));
        }
        $plain = Str::random(48);
        $this->secret = Hash::make($plain);
        $this->secret_expires_at = $ttlSeconds !== null ? $now->copy()->addSeconds($ttlSeconds) : null;
        $this->secret_rotated_at = $now;
        $this->save();

        return $plain;
    }

    /** true se il secret PRECEDENTE è ancora valido (dentro la finestra di grace). */
    public function previousSecretActive(): bool
    {
        return is_string($this->secret_previous) && $this->secret_previous !== ''
            && $this->secret_previous_expires_at !== null && $this->secret_previous_expires_at->isFuture();
    }
}
