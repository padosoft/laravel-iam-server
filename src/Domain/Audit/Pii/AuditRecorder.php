<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Audit\Pii;

use Padosoft\Iam\Contracts\Crypto\SecretCipher;
use Padosoft\Iam\Domain\Audit\AuditChainAppender;
use Padosoft\Iam\Domain\Audit\Models\AuditEvent;
use Padosoft\Iam\Domain\Audit\Webhooks\AuditEventPusher;

/**
 * Registra eventi di audit applicando privacy-by-default (doc 12 §7-§8): la PII viene cifrata con
 * una DEK PER-SOGGETTO (→ crypto-shredding GDPR), e ip/user-agent sono trattati secondo `ip_mode`/
 * `ua_mode` (hash con pepper | full | none) prima di sigillare l'evento nella hash-chain.
 */
final class AuditRecorder
{
    public function __construct(
        private readonly AuditChainAppender $appender,
        private readonly SecretCipher $cipher,
        // Opzionale (P2): un costruttore diretto senza pusher — com'è nei test — salta il push
        // webhook; il container lo inietta e ogni evento sigillato qui viene anche spinto alle
        // subscription attive (best-effort, mai bloccante — vedi AuditEventPusher).
        private readonly ?AuditEventPusher $pusher = null,
    ) {}

    /**
     * @param  array<string, mixed>  $attributes  attributi dell'evento (almeno stream + event_type)
     * @param  array<string, mixed>  $pii  dati personali da cifrare per-soggetto (vuoto = nessuno)
     */
    public function record(array $attributes, array $pii = [], ?string $subject = null, ?string $ip = null, ?string $userAgent = null): AuditEvent
    {
        $attributes['ip_hash'] = $this->transform($ip, 'ip_mode');
        $attributes['user_agent_hash'] = $this->transform($userAgent, 'ua_mode');

        if ($pii !== [] && $subject !== null) {
            $scope = $this->scope($subject);
            $attributes['pii_encrypted'] = $this->cipher->encrypt(
                json_encode($pii, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR),
                $scope,
            );
            $attributes['pii_dek_id'] = $scope;
        }

        $event = $this->appender->append($attributes);
        $this->pusher?->push($event);

        return $event;
    }

    /**
     * Decifra la PII di un evento. Ritorna null se non c'è PII o se la DEK del soggetto è stata
     * distrutta (crypto-shredding) → la PII è irreversibilmente illeggibile, ma l'hash resta valido.
     *
     * @return array<array-key, mixed>|null
     */
    public function readPii(AuditEvent $event): ?array
    {
        $envelope = $event->pii_encrypted;
        if (!is_array($envelope) || $envelope === []) {
            return null;
        }

        try {
            /** @var array{ciphertext: string, wrapped_dek: string|null, key_id: string, key_version: int, scope: string|null} $envelope */
            $plain = $this->cipher->decrypt($envelope);
            $decoded = json_decode($plain, true, 512, JSON_THROW_ON_ERROR);

            return is_array($decoded) ? $decoded : null;
        } catch (\Throwable) {
            return null; // DEK distrutta (shredded) o valore non più decifrabile
        }
    }

    public function scope(string $subject): string
    {
        return 'audit-pii:'.$subject;
    }

    /** Applica ip_mode/ua_mode: 'hash' (HMAC col pepper) | 'full' (in chiaro) | 'none' (niente). */
    private function transform(?string $value, string $modeKey): ?string
    {
        return PrivacyMode::apply($value, $modeKey);
    }
}
