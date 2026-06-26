<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Applications\Manifest;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Padosoft\Iam\Domain\Applications\Models\Application;
use Padosoft\Iam\Domain\Applications\Models\Manifest;
use Padosoft\Iam\Domain\Authorization\Models\Permission;
use Padosoft\Iam\Domain\Authorization\Models\Role;
use Padosoft\Iam\Domain\OAuth\Models\OauthClient;

/**
 * Applica un manifest APPROVED (doc 01 §10): upsert idempotente di Application + OAuth client
 * (il registry possiede il client) + permessi + ruoli + role_permissions, in transazione. Gli
 * elementi rimossi dal manifest sono deprecati (soft), non cancellati (audit). Ri-apply = no-op.
 */
final class ManifestApplier
{
    /** Secret in chiaro generato per un client confidential nuovo (da consegnare una sola volta). */
    private ?string $generatedSecret = null;

    public function apply(Manifest $manifest): Application
    {
        if ($manifest->status !== 'approved') {
            throw new \RuntimeException("Solo un manifest 'approved' è applicabile (status attuale: {$manifest->status}).");
        }

        $this->generatedSecret = null;
        $payload = $manifest->payload;
        $appKey = $manifest->application_key;
        $app = $this->arr($payload['app'] ?? null);

        $application = DB::transaction(function () use ($manifest, $payload, $appKey, $app): Application {
            $application = Application::query()->firstOrNew(['key' => $appKey]);

            // L'organizzazione di un'app esistente è immutabile: un manifest NON può trasferire
            // la proprietà cross-org (anti app-hijack). Mismatch → errore.
            if ($application->exists && $application->organization_id !== $manifest->organization_id) {
                throw new \RuntimeException("Il manifest non può cambiare l'organizzazione dell'app esistente \"{$appKey}\".");
            }
            if (!$application->exists) {
                $application->organization_id = $manifest->organization_id;
            }

            $application->fill([
                'name' => is_string($app['name'] ?? null) ? $app['name'] : $appKey,
                'type' => is_string($app['type'] ?? null) ? $app['type'] : 'laravel',
                'risk_level' => is_string($app['risk_level'] ?? null) ? $app['risk_level'] : 'low',
            ]);
            $application->save();

            $this->applyClient($appKey, $manifest->organization_id, $payload, $app);
            $this->applyPermissions($appKey, $payload);
            $this->applyRoles($appKey, $payload);

            $manifest->forceFill(['status' => 'applied', 'applied_at' => now()])->save();
            $application->forceFill(['current_manifest_id' => $manifest->id])->save();

            return $application;
        });

        return $application;
    }

    /**
     * @param  array<string, mixed>  $payload
     * @param  array<array-key, mixed>  $app
     */
    private function applyClient(string $appKey, ?string $organizationId, array $payload, array $app): void
    {
        $auth = $this->arr($payload['auth'] ?? null);
        $confidential = ($auth['client_type'] ?? 'confidential') === 'confidential';
        $type = is_string($app['type'] ?? null) ? $app['type'] : 'laravel';

        $client = OauthClient::query()->firstOrNew(['client_id' => 'cli_'.$appKey]);
        $hasSecret = is_string($client->secret) && $client->secret !== '';
        $client->fill([
            'name' => is_string($app['name'] ?? null) ? $app['name'] : $appKey,
            'redirect_uris' => array_values(array_filter($this->arr($auth['redirect_uris'] ?? null), 'is_string')),
            'grants' => $type === 'service' ? ['client_credentials'] : ['authorization_code', 'refresh_token'],
            'scopes' => $this->clientScopes($payload),
            'is_confidential' => $confidential,
            'is_first_party' => true, // le app del registry sono first-party
            'organization_id' => $organizationId,
            'application_key' => $appKey,
        ]);

        // Un client confidential ha bisogno di un secret (senza, fail-closed = inutilizzabile). Lo
        // generiamo quando manca: client NUOVO oppure transizione public→confidential di uno esistente
        // (che non aveva secret). Sui re-apply di un confidential che già ne ha uno NON si tocca
        // (la rotazione è un flusso a parte).
        if ($confidential && !$hasSecret) {
            $plain = Str::random(48);
            $client->secret = Hash::make($plain); // `secret` non è fillable: assegnazione diretta
            $this->generatedSecret = $plain;
        } elseif (!$confidential && $hasSecret) {
            // Transizione confidential→public: un client public non si autentica col secret, non
            // deve conservarne uno (igiene di stato). Tornerà confidential → nuovo secret.
            $client->secret = null;
        }

        $client->save();
    }

    /** Secret in chiaro del client appena creato (null se nessuno). Da consegnare/archiviare una volta. */
    public function generatedSecret(): ?string
    {
        return $this->generatedSecret;
    }

    /**
     * @param  array<string, mixed>  $payload
     */
    private function applyPermissions(string $appKey, array $payload): void
    {
        $declared = [];
        foreach ($this->arr($payload['permissions'] ?? null) as $perm) {
            if (!is_array($perm) || !is_string($perm['key'] ?? null) || $perm['key'] === '') {
                continue;
            }
            $key = $perm['key'];
            $declared[] = $key;
            $model = Permission::query()->firstOrNew(['full_key' => $appKey.':'.$key]);
            $model->fill([
                'app_key' => $appKey,
                'key' => $key,
                'resource' => is_string($perm['resource'] ?? null) ? $perm['resource'] : null,
                'action' => is_string($perm['action'] ?? null) ? $perm['action'] : null,
                'risk' => is_string($perm['risk'] ?? null) ? $perm['risk'] : 'low',
                'requires_step_up' => ($perm['requires_step_up'] ?? false) === true,
                'deprecated_at' => null, // ri-attiva se era deprecato
            ]);
            $model->save();
        }

        // Permessi dell'app non più dichiarati → deprecati (soft), non cancellati.
        Permission::query()
            ->where('app_key', $appKey)
            ->whereNotIn('key', $declared === [] ? [''] : $declared)
            ->whereNull('deprecated_at')
            ->update(['deprecated_at' => now()]);
    }

    /**
     * @param  array<string, mixed>  $payload
     */
    private function applyRoles(string $appKey, array $payload): void
    {
        $declared = [];
        foreach ($this->arr($payload['roles'] ?? null) as $role) {
            if (!is_array($role) || !is_string($role['key'] ?? null) || $role['key'] === '') {
                continue;
            }
            $key = $role['key'];
            $declared[] = $key;
            $model = Role::query()->firstOrNew(['full_key' => $appKey.':'.$key]);
            $model->fill([
                'app_key' => $appKey,
                'key' => $key,
                'label' => is_string($role['label'] ?? null) ? $role['label'] : null,
                'is_privileged' => ($role['is_privileged'] ?? false) === true,
                'deprecated_at' => null,
            ]);
            $model->save();

            // Sync role_permissions sulle permission dichiarate (full_key = app:permKey).
            $permKeys = array_values(array_filter($this->arr($role['permissions'] ?? null), 'is_string'));
            $permIds = Permission::query()
                ->where('app_key', $appKey)
                ->whereIn('key', $permKeys === [] ? [''] : $permKeys)
                ->pluck('id')
                ->all();
            $model->permissions()->sync($permIds);
        }

        Role::query()
            ->where('app_key', $appKey)
            ->whereNotIn('key', $declared === [] ? [''] : $declared)
            ->whereNull('deprecated_at')
            ->update(['deprecated_at' => now()]);
    }

    /**
     * Scope del client: OIDC standard + le chiavi dei permessi dichiarati.
     *
     * @param  array<string, mixed>  $payload
     * @return list<string>
     */
    private function clientScopes(array $payload): array
    {
        $scopes = ['openid', 'profile', 'email'];
        foreach ($this->arr($payload['permissions'] ?? null) as $perm) {
            if (is_array($perm) && is_string($perm['key'] ?? null) && $perm['key'] !== '') {
                $scopes[] = $perm['key'];
            }
        }

        return array_values(array_unique($scopes));
    }

    /**
     * @return array<array-key, mixed>
     */
    private function arr(mixed $value): array
    {
        return is_array($value) ? $value : [];
    }
}
