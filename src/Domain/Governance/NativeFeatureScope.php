<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Governance;

use Padosoft\Iam\Contracts\Governance\FeatureContext;
use Padosoft\Iam\Contracts\Governance\FeatureScope;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Iam\Domain\Authorization\Pdp\DecisionQuery;
use Padosoft\Iam\Domain\Authorization\Pdp\NativeSqlEngine;

/**
 * Implementazione nativa della primitiva FeatureScope (doc 14 §1). Risolve l'attivazione di una
 * feature di governance sulla cascata layer→app→role→user da `config('iam-governance')`: vince il
 * livello PIÙ SPECIFICO con un valore esplicito (user > role > app > default), `inherit` non conta.
 * Default sicuro (off salvo diversa config) + gate via permesso valutato dal PDP.
 */
final class NativeFeatureScope implements FeatureScope
{
    public function __construct(private readonly NativeSqlEngine $pdp) {}

    public function isEnabled(FeatureContext $ctx): bool
    {
        $cfg = $this->featureConfig($ctx);
        $state = $this->resolve($cfg, $ctx, 'enabled') ?? $this->default($cfg);

        // 'off' = spento; qualunque altro token esplicito (on/detect/enforce) = acceso.
        return $state !== 'off';
    }

    public function isPermitted(FeatureContext $ctx, SubjectRef $actor): bool
    {
        $cfg = $this->featureConfig($ctx);
        $permission = $cfg['permission'] ?? null;
        if (!is_string($permission) || $permission === '') {
            return true; // nessun gate di permesso configurato
        }

        $appKey = $ctx->applicationKey ?? $this->appFromPermission($permission);

        $decision = $this->pdp->decide(new DecisionQuery(
            subject: $actor,
            permission: $permission,
            organizationId: $ctx->organizationId,
            applicationKey: $appKey,
        ));

        return $decision->allowed;
    }

    public function mode(FeatureContext $ctx): string
    {
        $cfg = $this->featureConfig($ctx);

        return $this->resolve($cfg, $ctx, 'mode') ?? $this->default($cfg);
    }

    /**
     * @return array<array-key, mixed>
     */
    private function featureConfig(FeatureContext $ctx): array
    {
        $cfg = config('iam-governance.features.'.$ctx->feature->value, []);

        return is_array($cfg) ? $cfg : [];
    }

    /**
     * Cerca il valore esplicito di `$key` dal livello più specifico a quello meno specifico.
     *
     * @param  array<array-key, mixed>  $cfg
     */
    private function resolve(array $cfg, FeatureContext $ctx, string $key): ?string
    {
        $candidates = [];
        if ($ctx->subject !== null) {
            $candidates[] = $this->level($cfg, 'users', (string) $ctx->subject, $key);
        }
        if ($ctx->roleKey !== null) {
            $candidates[] = $this->level($cfg, 'roles', $ctx->roleKey, $key);
        }
        if ($ctx->applicationKey !== null) {
            $candidates[] = $this->level($cfg, 'apps', $ctx->applicationKey, $key);
        }

        foreach ($candidates as $value) {
            if ($this->isExplicit($value)) {
                return $value;
            }
        }

        return null;
    }

    /**
     * @param  array<array-key, mixed>  $cfg
     */
    private function level(array $cfg, string $bucket, string $id, string $key): ?string
    {
        $bucketCfg = $cfg[$bucket] ?? null;
        if (!is_array($bucketCfg)) {
            return null;
        }
        $entry = $bucketCfg[$id] ?? null;
        if (!is_array($entry)) {
            return null;
        }
        $value = $entry[$key] ?? null;

        return is_string($value) ? $value : null;
    }

    private function isExplicit(?string $value): bool
    {
        return $value !== null && $value !== '' && $value !== 'inherit';
    }

    /**
     * @param  array<array-key, mixed>  $cfg
     */
    private function default(array $cfg): string
    {
        $default = $cfg['default'] ?? 'off';

        return is_string($default) && $default !== '' ? $default : 'off';
    }

    private function appFromPermission(string $permission): ?string
    {
        $pos = strpos($permission, ':');

        return $pos !== false ? substr($permission, 0, $pos) : null;
    }
}
