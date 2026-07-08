<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Audit\Webhooks;

/**
 * Difesa SSRF sull'URL di destinazione di un webhook (doc 12 §6). Richiede https (http solo se
 * esplicitamente abilitato in dev), blocca gli IP LETTERALI in range loopback/privati/link-local — in
 * particolare l'endpoint metadata cloud 169.254.169.254 — e (IAM-15) RISOLVE l'hostname validando OGNI
 * IP restituito: un host che risolve a un indirizzo interno (DNS rebinding) viene bloccato.
 *
 * Per neutralizzare il TOCTOU rebinding (DNS che cambia tra check e connect), `safeResolveTarget()`
 * ritorna l'IP validato: il WebhookSender lo PINNA (CURLOPT_RESOLVE), così l'indirizzo dialato è
 * esattamente quello validato, non una nuova risoluzione.
 */
final class WebhookUrlGuard
{
    /** @var (callable(string): list<string>)|null risolutore host→IP iniettabile (default: DNS reale) */
    private $resolver;

    /**
     * @param  (callable(string): list<string>)|null  $resolver  override della risoluzione DNS (test/determinismo).
     *         Null (default, autowiring) usa gethostbynamel + dns_get_record.
     */
    public function __construct(?callable $resolver = null)
    {
        $this->resolver = $resolver;
    }

    public function isSafe(string $url): bool
    {
        return $this->safeResolveTarget($url) !== null;
    }

    /**
     * Valida l'URL e risolve l'host a un IP sicuro da pinnare. Ritorna null (fail-closed) se lo scheme
     * non è ammesso, se l'host è/risolve a un IP interno/riservato, o se la risoluzione DNS fallisce.
     *
     * @return array{host: string, port: int, ip: string}|null
     */
    public function safeResolveTarget(string $url): ?array
    {
        $parts = parse_url($url);
        if (!is_array($parts) || !isset($parts['scheme'], $parts['host'])) {
            return null;
        }

        $scheme = strtolower($parts['scheme']);
        $host = strtolower(trim($parts['host'], '[]'));

        $allowInsecure = (bool) config('iam.audit.webhook_allow_insecure', false);
        if ($scheme !== 'https' && !($scheme === 'http' && $allowInsecure)) {
            return null;
        }

        $port = is_int($parts['port'] ?? null) ? $parts['port'] : ($scheme === 'https' ? 443 : 80);

        // Host già IP letterale: deve essere pubblico. Nessuna risoluzione da pinnare (host == ip).
        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            return $this->isPublicIp($host) ? ['host' => $host, 'port' => $port, 'ip' => $host] : null;
        }

        // Forme numeriche NON canoniche (decimale "2130706433", shorthand "127.1", ottale "017",
        // esadecimale "0x7f.1"): filter_var non le riconosce come IP, ma i resolver le mappano a
        // 127.0.0.1 ecc. → bypass SSRF. Un hostname legittimo ha sempre un segmento alfabetico.
        if (preg_match('/^(0x[0-9a-f]+|[0-9]+)(\.(0x[0-9a-f]+|[0-9]+))*$/i', $host) === 1) {
            return null;
        }

        // IAM-15: risolvi l'hostname e valida OGNI IP (A + AAAA). Fail-closed: risoluzione vuota/fallita
        // → non sicuro; anche un solo IP interno/riservato → non sicuro (blocca il rebinding).
        $ips = $this->resolve($host);
        if ($ips === []) {
            return null;
        }
        foreach ($ips as $ip) {
            if (!$this->isPublicIp($ip)) {
                return null;
            }
        }

        // Pinna il primo IP validato: l'indirizzo dialato sarà quello validato (no seconda risoluzione).
        return ['host' => $host, 'port' => $port, 'ip' => $ips[0]];
    }

    private function isPublicIp(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false;
    }

    /**
     * Risolve l'host a tutti gli IPv4 (A) e IPv6 (AAAA). Ritorna [] su fallimento (fail-closed).
     *
     * @return list<string>
     */
    private function resolve(string $host): array
    {
        if ($this->resolver !== null) {
            return array_values(($this->resolver)($host));
        }

        $ips = [];

        $v4 = @gethostbynamel($host);
        if (is_array($v4)) {
            foreach ($v4 as $ip) {
                $ips[] = $ip;
            }
        }

        $aaaa = @dns_get_record($host, DNS_AAAA);
        if (is_array($aaaa)) {
            foreach ($aaaa as $rec) {
                if (isset($rec['ipv6']) && is_string($rec['ipv6'])) {
                    $ips[] = $rec['ipv6'];
                }
            }
        }

        return array_values(array_unique($ips));
    }
}
