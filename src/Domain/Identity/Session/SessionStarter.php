<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Identity\Session;

use Illuminate\Http\Request;
use Padosoft\Iam\Contracts\Assurance\Aal;
use Padosoft\Iam\Contracts\Identity\SessionMeta;
use Padosoft\Iam\Contracts\Identity\SessionRef;
use Padosoft\Iam\Contracts\Identity\SessionRegistry;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Iam\Domain\Audit\Pii\PrivacyMode;

/**
 * Avvia una sessione IAM al login (chiamato dal flusso Fortify/passkeys/federato, M5.4) e ne lega
 * il `sid` alla sessione Laravel, così /authorize lo ritrova e lo inserisce nei token (doc 10 §3).
 * IP/UA seguono `iam.audit.ip_mode`/`ua_mode` via {@see PrivacyMode} (stessa pepper/HMAC dell'audit, così
 * la stessa origine hasha identica in sessioni e audit): `hash` (default, privacy) salva l'HMAC salato;
 * `full` salva il valore in chiaro (forense, visibile solo a chi ha sessions.read); `none` non salva nulla.
 * Il device-fingerprint resta SEMPRE hashato. NB: in `full` l'IP è utile solo se `TrustProxies` è
 * configurato host-side, altrimenti `$request->ip()` è l'IP del proxy/load-balancer, non del client.
 */
final class SessionStarter
{
    public function __construct(private readonly SessionRegistry $sessions) {}

    public function start(string $userId, Request $request, Aal $aal = Aal::AAL1, ?string $organizationId = null): SessionRef
    {
        $meta = new SessionMeta(
            aal: $aal,
            organizationId: $organizationId,
            deviceFingerprintHash: PrivacyMode::hash($request->header('X-Device-Fingerprint')),
            ipHash: PrivacyMode::apply($request->ip(), 'ip_mode'),
            userAgentHash: PrivacyMode::apply($request->userAgent(), 'ua_mode'),
            idleTimeout: $this->timeout('idle_timeout', 1800),
            absoluteTimeout: $this->timeout('absolute_timeout', 43200),
        );

        $ref = $this->sessions->start(new SubjectRef('user', $userId), $meta);
        $request->session()->put('iam_sid', $ref->id);
        $request->session()->migrate(true); // anti session-fixation: rigenera l'ID al login

        return $ref;
    }

    private function timeout(string $key, int $default): int
    {
        $value = config('iam.authentication.session.'.$key, $default);

        return is_int($value) && $value > 0 ? $value : $default;
    }
}
