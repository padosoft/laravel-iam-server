<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Applications\Manifest;

use Padosoft\Iam\Domain\Applications\Models\Application;
use Padosoft\Iam\Domain\Applications\Models\Manifest;

/**
 * Registra e fa avanzare il lifecycle di un manifest (doc 01 §10.1): submit → validate → diff →
 * (approve) → apply, con reject e rollback.
 */
final class ManifestRegistry
{
    public function __construct(
        private readonly ManifestValidator $validator,
        private readonly ManifestDiffer $differ,
        private readonly ManifestApplier $applier,
    ) {}

    /**
     * @param  array<string, mixed>  $payload
     */
    public function submit(array $payload, ?string $submittedBy = null, ?string $organizationId = null): Manifest
    {
        $appKey = $this->appKey($payload);
        $schema = $payload['schema'] ?? null;
        $maxVersion = Manifest::query()->where('application_key', $appKey)->max('version');

        $manifest = Manifest::query()->create([
            'application_key' => $appKey,
            'organization_id' => $organizationId,
            'schema' => is_string($schema) && $schema !== '' ? $schema : 'laravel-iam.manifest.v2',
            'version' => (is_numeric($maxVersion) ? (int) $maxVersion : 0) + 1,
            'payload' => $payload,
            'submitted_by' => $submittedBy,
        ]);

        if ($this->validate($manifest)->valid) {
            $this->diff($manifest);
        }

        return $manifest;
    }

    public function validate(Manifest $manifest): ValidationResult
    {
        $result = $this->validator->validate($manifest->payload);
        $manifest->forceFill([
            'status' => $result->valid ? 'validated' : 'rejected',
            'validation_errors' => $result->valid ? null : $result->errors,
        ])->save();

        return $result;
    }

    /**
     * Calcola il diff vs lo stato applicato e porta il manifest a pending_approval (se un gate
     * lo richiede) o approved (change additivi a basso rischio). No-op se il manifest è rejected.
     *
     * @return array<string, mixed>
     */
    public function diff(Manifest $manifest): array
    {
        // Si diffa SOLO un manifest già validato (la validazione schema deve essere passata):
        // niente avanzamento ad approved/pending senza validazione.
        if ($manifest->status !== 'validated') {
            return [];
        }

        $diff = $this->differ->diff($manifest);
        $requiresApproval = ($diff['requires_approval'] ?? false) === true;
        $manifest->forceFill([
            'diff' => $diff,
            'requires_approval' => $requiresApproval,
            'status' => $requiresApproval ? 'pending_approval' : 'approved',
        ])->save();

        return $diff;
    }

    /** Approva un manifest in pending_approval (gate umano sui cambi sensibili). */
    public function approve(Manifest $manifest, ?string $approvedBy = null): bool
    {
        if ($manifest->status !== 'pending_approval') {
            return false;
        }
        $manifest->forceFill(['status' => 'approved', 'approved_by' => $approvedBy])->save();

        return true;
    }

    public function reject(Manifest $manifest, ?string $approvedBy = null): bool
    {
        if (!in_array($manifest->status, ['pending_approval', 'validated'], true)) {
            return false;
        }
        $manifest->forceFill(['status' => 'rejected', 'approved_by' => $approvedBy])->save();

        return true;
    }

    /** Applica un manifest approved (delega all'applier). */
    public function apply(Manifest $manifest): Application
    {
        return $this->applier->apply($manifest);
    }

    /**
     * Rollback: ri-applica la PRECEDENTE versione applicata dell'app (doc 01 §10.1). La versione
     * corrente passa a rolled_back. Ritorna null se non c'è una versione precedente a cui tornare.
     */
    public function rollback(string $appKey): ?Application
    {
        $app = Application::query()->where('key', $appKey)->first();
        if ($app === null || !is_string($app->current_manifest_id)) {
            return null;
        }

        $previous = Manifest::query()
            ->where('application_key', $appKey)
            ->where('status', 'applied')
            ->whereKeyNot($app->current_manifest_id)
            ->orderByDesc('version')
            ->first();
        if ($previous === null) {
            return null;
        }

        Manifest::query()->whereKey($app->current_manifest_id)->update(['status' => 'rolled_back']);
        $previous->forceFill(['status' => 'approved'])->save();

        return $this->applier->apply($previous);
    }

    /**
     * @param  array<string, mixed>  $payload
     */
    private function appKey(array $payload): string
    {
        $app = is_array($payload['app'] ?? null) ? $payload['app'] : [];
        $key = $app['key'] ?? null;

        return is_string($key) && $key !== '' ? $key : 'unknown';
    }
}
