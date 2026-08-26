<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Authorization\Simulation;

use Padosoft\Iam\Domain\Authorization\Models\PolicyProbe;
use Padosoft\Iam\Domain\Authorization\Pdp\NativeSqlEngine;

/**
 * Il corpus di regressione: le sonde che portano un esito ATTESO, valutate
 * contro lo stato corrente.
 *
 * È il complemento del blast radius e risponde a una domanda diversa. Il blast
 * radius chiede *"cosa cambierebbe se applicassi questo?"* — utile davanti a una
 * modifica specifica. La regressione chiede *"la policy dice ancora quello che
 * abbiamo deciso che dicesse?"* — utile senza avere nessuna modifica in mano,
 * perché l'autorità deriva anche da cose che nessuno considera un cambio di
 * policy: un utente sospeso, una relazione riscritta, un ruolo deprecato.
 *
 * Una sonda senza esito atteso è deliberatamente IGNORATA qui. Inventarle
 * un'aspettativa dal comportamento corrente trasformerebbe un bug in un
 * requisito, che è esattamente il modo in cui un corpus di regressione smette di
 * proteggere qualcosa.
 */
final class PolicyRegressionRunner
{
    public function __construct(private readonly NativeSqlEngine $engine) {}

    /**
     * @param  list<PolicyProbe>  $probes
     */
    public function run(array $probes): PolicyRegressionResult
    {
        $failures = [];
        $checked = 0;

        foreach ($probes as $probe) {
            if ($probe->expected_allowed === null) {
                continue;
            }

            $checked++;
            $decision = $this->engine->decide($probe->toQuery());

            if ($decision->allowed === $probe->expected_allowed) {
                continue;
            }

            $failures[] = [
                ...$probe->describe(),
                'actual_allowed' => $decision->allowed,
                'decision_id' => $decision->decisionId,
                'policy_version' => $decision->policyVersion,
                'explanation' => $decision->explanation,
            ];
        }

        return new PolicyRegressionResult($checked, count($probes) - $checked, $failures);
    }
}
