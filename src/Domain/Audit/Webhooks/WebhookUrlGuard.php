<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Audit\Webhooks;

/**
 * Difesa SSRF di base sull'URL di destinazione di un webhook (doc 12 §6). Richiede https (http solo
 * se esplicitamente abilitato in dev) e blocca gli IP LETTERALI in range loopback/privati/link-local
 * — in particolare l'endpoint metadata cloud 169.254.169.254, bersaglio classico dell'SSRF.
 *
 * Limite noto (v1.x): un hostname che RISOLVE a un IP interno (DNS rebinding) non è bloccato qui —
 * servirebbe un client HTTP con resolver pinned. Documentato, non silenzioso.
 */
final class WebhookUrlGuard
{
    public function isSafe(string $url): bool
    {
        $parts = parse_url($url);
        if (!is_array($parts) || !isset($parts['scheme'], $parts['host'])) {
            return false;
        }

        $scheme = strtolower($parts['scheme']);
        $host = strtolower(trim($parts['host'], '[]'));

        $allowInsecure = (bool) config('iam.audit.webhook_allow_insecure', false);
        if ($scheme !== 'https' && !($scheme === 'http' && $allowInsecure)) {
            return false;
        }

        // Host = IP letterale → deve essere pubblico (no loopback/privato/riservato/link-local).
        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            return filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false;
        }

        // Forme numeriche NON canoniche (decimale "2130706433", shorthand "127.1", ottale "017",
        // esadecimale "0x7f.1"): filter_var non le riconosce come IP, ma i resolver OS/HTTP le
        // mappano a 127.0.0.1 ecc. → bypass SSRF. Un hostname legittimo ha sempre un segmento alfabetico.
        if (preg_match('/^(0x[0-9a-f]+|[0-9]+)(\.(0x[0-9a-f]+|[0-9]+))*$/i', $host) === 1) {
            return false;
        }

        return true;
    }
}
