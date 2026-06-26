<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Identity\Session;

use Padosoft\Iam\Contracts\Crypto\TokenSigner;

/**
 * Emette il logout_token OIDC Back-Channel Logout (doc 10 §3): JWT firmato (stesso TokenSigner
 * ES256 + JWKS) con `sid`, `events` con l'evento di back-channel logout e SENZA nonce. Inviato
 * alle app downstream con sessione attiva quando una sessione viene revocata. La consegna
 * (webhook) è del layer audit/events (M7); qui produciamo il token.
 */
final class LogoutTokenIssuer
{
    private const EVENT = 'http://schemas.openid.net/event/backchannel-logout';

    public function __construct(private readonly TokenSigner $signer) {}

    public function issue(string $sid, ?string $subject, string $audience): string
    {
        $claims = [
            'aud' => $audience,
            'sid' => $sid,
            // L'evento DEVE essere un oggetto JSON (anche vuoto): (object) [] → {}.
            'events' => [self::EVENT => (object) []],
        ];
        if ($subject !== null && $subject !== '') {
            $claims['sub'] = $subject;
        }

        // TTL breve: il logout_token è single-use e consumato subito dalle app.
        return $this->signer->issue($claims, 120);
    }
}
