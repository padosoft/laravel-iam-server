<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Applications\Manifest;

use Padosoft\Iam\Domain\Applications\Models\Application;
use Padosoft\Iam\Domain\Applications\Models\Manifest;

/**
 * Calcola il diff tra un manifest e lo stato APPLICATO corrente dell'app (doc 01 §10.1) e ne
 * classifica i cambi: `breaking` (rimozione di permission) e `requires_approval` (cambio
 * redirect_uri, cambio client_type, permission high/critical nuovi/modificati, ruolo con
 * permission critical). Permette change additivi a basso rischio senza approval.
 */
final class ManifestDiffer
{
    private const HIGH_RISK = ['high', 'critical'];

    /**
     * @return array<string, mixed>
     */
    public function diff(Manifest $manifest): array
    {
        $current = $this->currentPayload($manifest->application_key);
        $next = $manifest->payload;

        $permissions = $this->diffKeyed($this->items($current, 'permissions'), $this->items($next, 'permissions'));
        $roles = $this->diffKeyed($this->items($current, 'roles'), $this->items($next, 'roles'));
        $redirects = $this->diffList($this->redirects($current), $this->redirects($next));
        $clientType = $this->scalar($current, 'auth', 'client_type') !== $this->scalar($next, 'auth', 'client_type');

        $breaking = $permissions['removed'] !== [];
        $requiresApproval = $breaking
            || $redirects['added'] !== [] || $redirects['removed'] !== []
            || $clientType
            || $this->touchesHighRiskPermission($permissions, $current, $next)
            || $this->roleGrantsCriticalPermission($next);

        return [
            'permissions' => $permissions,
            'roles' => $roles,
            'redirect_uris' => $redirects,
            'client_type_changed' => $clientType,
            'breaking' => $breaking,
            'requires_approval' => $requiresApproval,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function currentPayload(string $appKey): array
    {
        $app = Application::query()->where('key', $appKey)->first();
        if ($app === null || !is_string($app->current_manifest_id)) {
            return [];
        }
        $applied = Manifest::query()->whereKey($app->current_manifest_id)->first();

        return $applied !== null ? $applied->payload : [];
    }

    /**
     * @param  array<string, array<array-key, mixed>>  $old
     * @param  array<string, array<array-key, mixed>>  $new
     * @return array{added: list<string>, changed: list<string>, removed: list<string>}
     */
    private function diffKeyed(array $old, array $new): array
    {
        $added = $changed = $removed = [];
        foreach ($new as $key => $item) {
            if (!array_key_exists($key, $old)) {
                $added[] = $key;
            } elseif ($this->canonical($old[$key]) !== $this->canonical($item)) {
                // Confronto canonico (ordine delle chiavi irrilevante): evita falsi "changed".
                $changed[] = $key;
            }
        }
        foreach (array_keys($old) as $key) {
            if (!array_key_exists($key, $new)) {
                $removed[] = $key;
            }
        }

        return ['added' => $added, 'changed' => $changed, 'removed' => $removed];
    }

    /**
     * @param  list<string>  $old
     * @param  list<string>  $new
     * @return array{added: list<string>, removed: list<string>}
     */
    private function diffList(array $old, array $new): array
    {
        return [
            'added' => array_values(array_diff($new, $old)),
            'removed' => array_values(array_diff($old, $new)),
        ];
    }

    /**
     * Mappa una lista di oggetti `{key: ...}` per key (per il confronto).
     *
     * @param  array<string, mixed>  $payload
     * @return array<string, array<array-key, mixed>>
     */
    private function items(array $payload, string $section): array
    {
        $out = [];
        $list = is_array($payload[$section] ?? null) ? $payload[$section] : [];
        foreach ($list as $item) {
            if (is_array($item) && is_string($item['key'] ?? null) && $item['key'] !== '') {
                $out[$item['key']] = $item;
            }
        }

        return $out;
    }

    /**
     * @param  array<string, mixed>  $payload
     * @return list<string>
     */
    private function redirects(array $payload): array
    {
        $auth = is_array($payload['auth'] ?? null) ? $payload['auth'] : [];
        $uris = is_array($auth['redirect_uris'] ?? null) ? $auth['redirect_uris'] : [];

        return array_values(array_filter($uris, 'is_string'));
    }

    /**
     * @param  array<string, mixed>  $payload
     */
    private function scalar(array $payload, string $section, string $key): ?string
    {
        $sec = is_array($payload[$section] ?? null) ? $payload[$section] : [];
        $value = $sec[$key] ?? null;

        return is_string($value) ? $value : null;
    }

    /**
     * Un cambio che TOCCA un permesso high/critical richiede approval. Per i permessi `changed`
     * si guarda il rischio sia VECCHIO sia NUOVO: così un downgrade critical→low (decisione di
     * sicurezza) non si auto-approva.
     *
     * @param  array{added: list<string>, changed: list<string>, removed: list<string>}  $permissions
     * @param  array<string, mixed>  $current
     * @param  array<string, mixed>  $next
     */
    private function touchesHighRiskPermission(array $permissions, array $current, array $next): bool
    {
        $newByKey = $this->items($next, 'permissions');
        foreach ($permissions['added'] as $key) {
            if (in_array($newByKey[$key]['risk'] ?? 'low', self::HIGH_RISK, true)) {
                return true;
            }
        }

        $oldByKey = $this->items($current, 'permissions');
        foreach ($permissions['changed'] as $key) {
            $oldRisk = $oldByKey[$key]['risk'] ?? 'low';
            $newRisk = $newByKey[$key]['risk'] ?? 'low';
            if (in_array($oldRisk, self::HIGH_RISK, true) || in_array($newRisk, self::HIGH_RISK, true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Forma canonica per il confronto: chiavi ordinate ricorsivamente.
     */
    private function canonical(mixed $value): mixed
    {
        if (!is_array($value)) {
            return $value;
        }
        $out = [];
        foreach ($value as $k => $v) {
            $out[$k] = $this->canonical($v);
        }
        ksort($out);

        return $out;
    }

    /**
     * @param  array<string, mixed>  $next
     */
    private function roleGrantsCriticalPermission(array $next): bool
    {
        $permRisk = [];
        foreach ($this->items($next, 'permissions') as $key => $perm) {
            $permRisk[$key] = is_string($perm['risk'] ?? null) ? $perm['risk'] : 'low';
        }
        foreach ($this->items($next, 'roles') as $role) {
            $perms = is_array($role['permissions'] ?? null) ? $role['permissions'] : [];
            foreach ($perms as $ref) {
                if (is_string($ref) && ($permRisk[$ref] ?? 'low') === 'critical') {
                    return true;
                }
            }
        }

        return false;
    }
}
