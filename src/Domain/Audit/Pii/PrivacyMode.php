<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Audit\Pii;

/**
 * Single source of truth for how IP/User-Agent are stored under `iam.audit.ip_mode`/`ua_mode`
 * (doc 12). Used by BOTH the audit pipeline (AuditRecorder) and the session pipeline (SessionStarter)
 * so a value hashes identically in `iam_audit_events` and `iam_sessions` (forensic correlation by
 * equality) and the privacy guarantees can never diverge between the two.
 *
 * Modes: `hash` (default) → salted HMAC-SHA256 (pepper mandatory in production, fail-closed); `full` →
 * the clear value (length-capped) for forensics, surfaced only to permissioned operators; `none` → null.
 */
final class PrivacyMode
{
    /** Max clear length persisted in `full` mode (real User-Agents can be long; guard the column). */
    private const MAX_CLEAR = 1024;

    /** Apply the configured mode to an IP/UA value. */
    public static function apply(?string $value, string $modeKey): ?string
    {
        if ($value === null || $value === '') {
            return null;
        }

        $mode = config('iam.audit.'.$modeKey, 'hash');
        if ($mode === 'none') {
            return null;
        }
        if ($mode === 'full') {
            return mb_substr($value, 0, self::MAX_CLEAR);
        }

        return self::hash($value);
    }

    /**
     * Always-hash (for values that must NEVER be stored in clear regardless of mode, e.g. the device
     * fingerprint). Salted HMAC-SHA256; fail-closed on a missing pepper in production.
     */
    public static function hash(?string $value): ?string
    {
        if ($value === null || $value === '') {
            return null;
        }

        return hash_hmac('sha256', $value, self::pepper());
    }

    /**
     * Secret pepper for the HMAC. Without it, an empty-key HMAC over an IP is brute-forceable
     * (~4B IPv4, precomputable) → the pseudonymization is worthless. Mandatory in production
     * (fail-closed); derived from APP_KEY in dev/test.
     */
    public static function pepper(): string
    {
        $pepper = config('iam.audit.ip_pepper');
        if (is_string($pepper) && $pepper !== '') {
            return $pepper;
        }

        if (app()->environment('production')) {
            throw new \RuntimeException('iam.audit.ip_pepper obbligatorio in produzione quando ip_mode/ua_mode=hash.');
        }

        $appKey = config('app.key');
        if (!is_string($appKey) || $appKey === '') {
            throw new \RuntimeException('APP_KEY assente: impossibile derivare un pepper di sviluppo.');
        }

        return hash('sha256', 'iam-audit-ip|'.$appKey);
    }
}
