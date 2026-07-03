<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Identity\Session;

use Illuminate\Http\Request;
use Padosoft\Iam\Contracts\Assurance\Aal;
use Padosoft\Iam\Contracts\Identity\SessionMeta;
use Padosoft\Iam\Contracts\Identity\SessionRef;
use Padosoft\Iam\Contracts\Identity\SessionRegistry;
use Padosoft\Iam\Contracts\Support\SubjectRef;

/**
 * Avvia una sessione IAM al login (chiamato dal flusso Fortify/passkeys/federato, M5.4) e ne lega
 * il `sid` alla sessione Laravel, così /authorize lo ritrova e lo inserisce nei token (doc 10 §3).
 * IP/UA seguono `iam.audit.ip_mode`/`ua_mode` (doc 12): `hash` (default, privacy) salva solo l'hash
 * salato; `full` salva il valore in chiaro (forense: correlazione per uguaglianza, visibile solo a chi
 * ha il permesso sessions.read); `none` non salva nulla. Il device-fingerprint resta sempre hashato.
 */
final class SessionStarter
{
    public function __construct(private readonly SessionRegistry $sessions) {}

    public function start(string $userId, Request $request, Aal $aal = Aal::AAL1, ?string $organizationId = null): SessionRef
    {
        $meta = new SessionMeta(
            aal: $aal,
            organizationId: $organizationId,
            deviceFingerprintHash: $this->hash($request->header('X-Device-Fingerprint')),
            ipHash: $this->transform($request->ip(), 'ip_mode'),
            userAgentHash: $this->transform($request->userAgent(), 'ua_mode'),
            idleTimeout: $this->timeout('idle_timeout', 1800),
            absoluteTimeout: $this->timeout('absolute_timeout', 43200),
        );

        $ref = $this->sessions->start(new SubjectRef('user', $userId), $meta);
        $request->session()->put('iam_sid', $ref->id);
        $request->session()->migrate(true); // anti session-fixation: rigenera l'ID al login

        return $ref;
    }

    /**
     * Applica `iam.audit.<modeKey>` a un valore IP/UA: none → null, full → in chiaro, altrimenti hash salato.
     * La colonna resta `*_hash` ma in modalità `full` contiene il valore leggibile (come per l'audit).
     */
    private function transform(?string $value, string $modeKey): ?string
    {
        if ($value === null || $value === '') {
            return null;
        }
        $mode = config('iam.audit.'.$modeKey, 'hash');
        if ($mode === 'none') {
            return null;
        }

        return $mode === 'full' ? $value : $this->hash($value);
    }

    private function hash(?string $value): ?string
    {
        if ($value === null || $value === '') {
            return null;
        }
        $pepper = config('iam.audit.ip_pepper');

        return hash('sha256', (is_string($pepper) ? $pepper : '').'|'.$value);
    }

    private function timeout(string $key, int $default): int
    {
        $value = config('iam.authentication.session.'.$key, $default);

        return is_int($value) && $value > 0 ? $value : $default;
    }
}
