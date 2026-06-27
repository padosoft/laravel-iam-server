<?php

declare(strict_types=1);

namespace Padosoft\Iam\Observability;

use Illuminate\Support\Facades\DB;

/**
 * Readiness check del control plane (M14, deploy base). Distingue LIVENESS (il processo risponde) da
 * READINESS (le dipendenze critiche sono pronte: DB raggiungibile, KEK configurata). Un orchestratore
 * (k8s/Docker) instrada traffico solo quando `ready` è true; finché non lo è, il pod resta fuori dal
 * load balancer invece di servire 500. Fail-closed: una dipendenza che esplode → not ready, non "ok".
 */
final class HealthCheck
{
    /**
     * @return array{ready: bool, checks: array<string, bool>}
     */
    public function run(): array
    {
        $checks = [
            'database' => $this->database(),
            'crypto_kek' => $this->cryptoKek(),
        ];

        return [
            'ready' => !in_array(false, $checks, true),
            'checks' => $checks,
        ];
    }

    private function database(): bool
    {
        try {
            DB::connection()->getPdo();

            return true;
        } catch (\Throwable) {
            return false;
        }
    }

    private function cryptoKek(): bool
    {
        $kek = config('iam.crypto.kek');

        return is_string($kek) && $kek !== '';
    }
}
