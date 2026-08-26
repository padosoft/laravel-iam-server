<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Authorization\Simulation;

use Illuminate\Support\Facades\DB;
use Padosoft\Iam\Domain\Authorization\Models\PolicyProbe;
use Padosoft\Iam\Domain\Authorization\Pdp\Decision;
use Padosoft\Iam\Domain\Authorization\Pdp\NativeSqlEngine;
use Throwable;

/**
 * *"Cosa succederebbe se applicassimo questo?"* — misurato eseguendo davvero il
 * cambiamento e poi tornando indietro.
 *
 * Il metodo è deliberatamente concreto invece che analitico. Un simulatore che
 * ragiona sul cambiamento — "questo grant aggiunge il permesso X al ruolo Y,
 * quindi presumibilmente…" — è un secondo motore di autorizzazione, e da quel
 * momento esistono due verità che possono divergere: il PDP e il modello di ciò
 * che il PDP farebbe. Qui il cambiamento viene applicato dentro una transazione,
 * le sonde vengono valutate **dal PDP vero**, e la transazione viene annullata.
 * Non c'è una seconda verità da tenere allineata.
 *
 * Il prezzo, dichiarato:
 *
 *  - **Non si committa mai.** L'uscita dalla transazione è sempre
 *    {@see SimulationRollback}; non esiste un ramo che committa. Se un giorno ne
 *    comparisse uno, sarebbe la peggior classe di bug possibile in questo file.
 *  - **Il cambiamento gira davvero.** Scritture, lock, trigger: tutto accade e
 *    viene annullato. Ciò che NON viene annullato è quello che esce dal database
 *    — job in coda, webhook, chiamate HTTP. Un `$change` che ne produce non è
 *    simulabile, e chi lo passa deve saperlo: qui l'unico chiamante è
 *    l'applicazione di un manifest, che è transazionale per costruzione.
 *  - **Su una connessione già in transazione** il rollback usa un savepoint, e
 *    annulla solo la parte della simulazione. Il lavoro del chiamante resta.
 */
final class BlastRadiusSimulator
{
    public function __construct(private readonly NativeSqlEngine $engine) {}

    /**
     * @param  list<PolicyProbe>  $probes
     * @param  callable(): void  $change  la mutazione proposta, eseguita e poi annullata
     *
     * @throws Throwable qualsiasi errore REALE del cambiamento risale: una
     *                   simulazione che fallisce e tace sarebbe letta come "nessun impatto"
     */
    public function simulate(array $probes, callable $change): BlastRadiusReport
    {
        $before = $this->evaluate($probes);

        /** @var array<string, Decision> $after */
        $after = [];

        try {
            DB::transaction(function () use ($change, $probes, &$after): void {
                $change();
                $after = $this->evaluate($probes);

                // L'unica uscita. Misurare non deve poter diventare applicare.
                throw new SimulationRollback('Simulation complete — rolling back.');
            });
        } catch (SimulationRollback) {
            // Atteso: è così che si annulla `DB::transaction`.
        }

        $outcomes = [];

        foreach ($probes as $probe) {
            $b = $before[$probe->id] ?? null;
            $a = $after[$probe->id] ?? null;

            if ($b === null || $a === null) {
                continue;
            }

            $outcomes[] = new ProbeOutcome(
                probe: $probe,
                before: $b->allowed,
                after: $a->allowed,
                stepUpBefore: $b->requiresStepUp,
                stepUpAfter: $a->requiresStepUp,
                explanationAfter: $a->explanation,
            );
        }

        return new BlastRadiusReport($outcomes);
    }

    /**
     * @param  list<PolicyProbe>  $probes
     * @return array<string, Decision>
     */
    private function evaluate(array $probes): array
    {
        $decisions = [];

        foreach ($probes as $probe) {
            $decisions[$probe->id] = $this->engine->decide($probe->toQuery());
        }

        return $decisions;
    }
}
