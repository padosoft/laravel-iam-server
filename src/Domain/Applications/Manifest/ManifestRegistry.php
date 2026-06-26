<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Applications\Manifest;

use Padosoft\Iam\Domain\Applications\Models\Manifest;

/**
 * Registra e fa avanzare il lifecycle di un manifest (doc 01 §10.1). M6.1: submit + validate
 * (submitted → validated|rejected). Diff/apply/approval nelle slice successive.
 */
final class ManifestRegistry
{
    public function __construct(
        private readonly ManifestValidator $validator,
        private readonly ManifestDiffer $differ,
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
        if ($manifest->status === 'rejected') {
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
