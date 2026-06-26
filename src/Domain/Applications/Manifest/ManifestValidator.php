<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Applications\Manifest;

/**
 * Valida un manifest `laravel-iam.manifest.v2` (doc 01 §10): campi richiesti, slug immutabili
 * ben formati, risk levels, redirect_uris esatte (no wildcard), coerenza referenziale
 * (i ruoli referenziano permessi dichiarati). Funzione pura sull'array del manifest.
 */
final class ManifestValidator
{
    private const RISK = ['low', 'medium', 'high', 'critical'];

    /**
     * @param  array<string, mixed>  $manifest
     */
    public function validate(array $manifest): ValidationResult
    {
        $errors = [];

        if (($manifest['schema'] ?? null) !== 'laravel-iam.manifest.v2') {
            $errors[] = 'schema deve essere "laravel-iam.manifest.v2"';
        }

        $app = $this->arr($manifest['app'] ?? null);
        $appKey = $app['key'] ?? null;
        if (!is_string($appKey) || !$this->isValidKey($appKey)) {
            $errors[] = 'app.key mancante o malformato (slug [a-z][a-z0-9_.-]*)';
        }
        if (!is_string($app['name'] ?? null) || ($app['name'] ?? '') === '') {
            $errors[] = 'app.name richiesto';
        }
        if (!in_array($app['risk_level'] ?? 'low', self::RISK, true)) {
            $errors[] = 'app.risk_level non valido (low|medium|high|critical)';
        }

        $auth = $this->arr($manifest['auth'] ?? null);
        if (!in_array($auth['client_type'] ?? 'confidential', ['confidential', 'public'], true)) {
            $errors[] = 'auth.client_type non valido (confidential|public)';
        }
        foreach ($this->arr($auth['redirect_uris'] ?? null) as $uri) {
            if (!$this->isValidRedirect($uri)) {
                $errors[] = 'auth.redirect_uris contiene una URI non valida (assoluta, no wildcard): '.(is_string($uri) ? $uri : 'n/d');
            }
        }

        $permissionKeys = [];
        foreach ($this->arr($manifest['permissions'] ?? null) as $index => $perm) {
            if (!is_array($perm)) {
                $errors[] = "permissions[{$index}] non è un oggetto";

                continue;
            }
            $key = $perm['key'] ?? null;
            if (!is_string($key) || !$this->isValidKey($key)) {
                $errors[] = "permissions[{$index}].key mancante o malformato";

                continue;
            }
            $permissionKeys[] = $key;
            if (!in_array($perm['risk'] ?? 'low', self::RISK, true)) {
                $errors[] = "permissions[{$key}].risk non valido";
            }
        }

        foreach ($this->arr($manifest['roles'] ?? null) as $index => $role) {
            if (!is_array($role)) {
                $errors[] = "roles[{$index}] non è un oggetto";

                continue;
            }
            $key = $role['key'] ?? null;
            if (!is_string($key) || !$this->isValidKey($key)) {
                $errors[] = "roles[{$index}].key mancante o malformato";

                continue;
            }
            foreach ($this->arr($role['permissions'] ?? null) as $ref) {
                if (!in_array($ref, $permissionKeys, true)) {
                    $errors[] = "roles[{$key}] referenzia un permission non dichiarato: ".(is_string($ref) ? $ref : 'n/d');
                }
            }
        }

        return $errors === [] ? ValidationResult::ok() : ValidationResult::fail($errors);
    }

    private function isValidKey(string $key): bool
    {
        return preg_match('/^[a-z][a-z0-9_.-]*$/', $key) === 1;
    }

    private function isValidRedirect(mixed $uri): bool
    {
        return is_string($uri)
            && !str_contains($uri, '*')
            && filter_var($uri, FILTER_VALIDATE_URL) !== false;
    }

    /**
     * @return array<array-key, mixed>
     */
    private function arr(mixed $value): array
    {
        return is_array($value) ? $value : [];
    }
}
