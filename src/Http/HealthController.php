<?php

declare(strict_types=1);

namespace Padosoft\Iam\Http;

use Illuminate\Http\JsonResponse;
use Padosoft\Iam\Observability\HealthCheck;

/**
 * Endpoint di liveness/readiness (M14, deploy base). NON autenticati (devono rispondere anche prima
 * che l'app sia pronta e senza credenziali, per orchestratore/load balancer). `live` = il processo
 * gira (200 sempre). `ready` = dipendenze critiche pronte (200) oppure 503 finché non lo sono, così
 * il traffico non viene instradato verso un'istanza non pronta.
 *
 * Information disclosure: essendo PUBBLICI, gli endpoint espongono SOLO lo status (il codice HTTP è
 * ciò che serve a k8s/LB). Il dettaglio per-check (quale dipendenza è giù) NON va in chiaro a un
 * anonimo — rivelerebbe lo stato interno (es. crypto disabilitata). Resta nei log/audit.
 */
final class HealthController
{
    public function live(): JsonResponse
    {
        return new JsonResponse(['status' => 'ok'], 200);
    }

    public function ready(HealthCheck $health): JsonResponse
    {
        $ready = $health->run()['ready'];

        return new JsonResponse(
            ['status' => $ready ? 'ready' : 'unavailable'],
            $ready ? 200 : 503,
        );
    }
}
