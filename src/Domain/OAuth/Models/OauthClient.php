<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\OAuth\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Crypt;
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
 * @property bool $auto_rotate
 * @property int|null $rotate_interval_days
 * @property string|null $secret_pending_encrypted
 * @property array<string, mixed>|null $jwks
 * @property string|null $token_endpoint_auth_method
 */
final class OauthClient extends Model
{
    use HasUlids;

    protected $table = 'iam_oauth_clients';

    /** @var list<string> secret e revoked_at sono fuori da fillable: valorizzati via metodi controllati. */
    protected $fillable = [
        'client_id', 'name', 'redirect_uris', 'grants', 'scopes',
        'is_confidential', 'is_first_party', 'organization_id', 'application_key',
        'auto_rotate', 'rotate_interval_days',
        'jwks', 'token_endpoint_auth_method',
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
        'auto_rotate' => 'boolean',
        'jwks' => 'array',
    ];

    /** True when this client authenticates with a signed assertion (private_key_jwt), not a shared secret. */
    public function usesPrivateKeyJwt(): bool
    {
        return $this->token_endpoint_auth_method === 'private_key_jwt';
    }

    /** @var list<string> Hash dei secret + il pending cifrato non vanno mai serializzati. */
    protected $hidden = ['secret', 'secret_previous', 'secret_pending_encrypted'];

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
    public function rotateSecret(int $graceSeconds, ?int $ttlSeconds, bool $storeForPickup = false): string
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
        // Auto-rotation: nessun umano riceve il secret → lo teniamo CIFRATO (recuperabile, app-key) per il
        // self-fetch dell'app durante il grace. Rotazione manuale: l'admin lo riceve → nessun pending.
        $this->secret_pending_encrypted = $storeForPickup ? Crypt::encryptString($plain) : null;
        $this->save();

        return $plain;
    }

    /** true se il secret PRECEDENTE è ancora valido (dentro la finestra di grace). */
    public function previousSecretActive(): bool
    {
        return is_string($this->secret_previous) && $this->secret_previous !== ''
            && $this->secret_previous_expires_at !== null && $this->secret_previous_expires_at->isFuture();
    }

    /** true se il client va auto-ruotato ORA (opt-in, intervallo scaduto, nessuna rotazione già in corso). */
    public function dueForRotation(): bool
    {
        if (!$this->auto_rotate || !$this->is_confidential || $this->revoked_at !== null || $this->previousSecretActive()) {
            return false;
        }
        $days = $this->rotate_interval_days;
        if ($days === null || $days <= 0) {
            return false;
        }

        return $this->secret_rotated_at === null || $this->secret_rotated_at->copy()->addDays($days)->isPast();
    }

    /** Il secret pending (nuovo) in chiaro, per il self-fetch dell'app durante il grace; null se assente. */
    public function pendingSecret(): ?string
    {
        if (!is_string($this->secret_pending_encrypted) || $this->secret_pending_encrypted === '') {
            return null;
        }
        try {
            return Crypt::decryptString($this->secret_pending_encrypted);
        } catch (\Throwable) {
            return null;
        }
    }

    public function clearPendingSecret(): void
    {
        if ($this->secret_pending_encrypted !== null) {
            $this->secret_pending_encrypted = null;
            $this->save();
        }
    }
}
