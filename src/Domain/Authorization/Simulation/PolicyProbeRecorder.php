<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Authorization\Simulation;

use Illuminate\Database\QueryException;
use Padosoft\Iam\Domain\Authorization\Models\PolicyProbe;
use Padosoft\Iam\Domain\Authorization\Pdp\DecisionQuery;

/**
 * Costruisce il corpus dalle decisioni VERE, campionandole.
 *
 * Un corpus scritto solo a mano copre i casi a cui qualcuno ha pensato — cioè
 * quelli che già considera importanti, che sono raramente quelli che si rompono.
 * Campionare il traffico copre ciò che l'applicazione fa davvero, comprese le
 * combinazioni che nessuno avrebbe scritto.
 *
 * Tre vincoli, tutti perché registrare non deve costare quanto decidere:
 *
 *  - **campionato**, non esaustivo (`sample_rate`, default 0): un IAM che scrive
 *    una riga per ogni check ha appena raddoppiato le proprie scritture;
 *  - **deduplicato** sul digest della tupla, così una sonda ricorrente aggiorna
 *    `last_seen_at` invece di moltiplicarsi;
 *  - **con un tetto** (`max_probes`): oltre quello smette di registrare invece
 *    di crescere per sempre. Un corpus che non entra in una revisione umana non
 *    viene revisionato.
 *
 * Le sonde registrate nascono SENZA esito atteso: sono materiale da leggere e
 * promuovere, non asserzioni. Promuoverle automaticamente al comportamento
 * corrente trasformerebbe ogni bug esistente in un requisito.
 *
 * Non registra mai il `context`: è il posto dove finiscono attributi arbitrari
 * della richiesta, e questa tabella non è il posto per farli sedimentare.
 */
final class PolicyProbeRecorder
{
    public function __construct(
        private readonly float $sampleRate = 0.0,
        private readonly int $maxProbes = 5000,
    ) {}

    public function record(DecisionQuery $query): void
    {
        if ($this->sampleRate <= 0.0) {
            return;
        }

        // Campionamento deterministico sul digest, non casuale: una tupla
        // ricorrente o entra sempre nel corpus o non entra mai, invece di
        // apparire e sparire fra due esecuzioni della stessa CI.
        $hash = PolicyProbe::hashOf(
            $query->subject,
            $query->permission,
            $query->resourceRef,
            [],
            $query->organizationId,
            $query->currentAal,
            $query->applicationKey,
        );

        if (!$this->sampled($hash)) {
            return;
        }

        try {
            $existing = PolicyProbe::query()->where('probe_hash', $hash)->first();

            if ($existing !== null) {
                $existing->forceFill(['last_seen_at' => now()])->save();

                return;
            }

            if (PolicyProbe::query()->count() >= $this->maxProbes) {
                return;
            }

            PolicyProbe::query()->create([
                'id' => PolicyProbe::newId(),
                'organization_id' => $query->organizationId,
                'application_key' => $query->applicationKey,
                'subject_type' => $query->subject->type,
                'subject_id' => $query->subject->id,
                'permission' => $query->permission,
                'resource_ref' => $query->resourceRef,
                'context' => null,
                'current_aal' => $query->currentAal,
                'expected_allowed' => null,
                'source' => PolicyProbe::SOURCE_RECORDED,
                'probe_hash' => $hash,
                'last_seen_at' => now(),
            ]);
        } catch (QueryException) {
            // Registrare è opportunistico: una corsa sull'unique, o una tabella
            // non ancora migrata, non deve MAI far fallire una decisione di
            // autorizzazione. Il corpus è uno strumento; il PDP è il prodotto.
        }
    }

    /**
     * Frazione deterministica in [0,1) derivata dal digest.
     */
    private function sampled(string $hash): bool
    {
        if ($this->sampleRate >= 1.0) {
            return true;
        }

        $bucket = hexdec(substr(hash('sha256', $hash), 0, 6)) / 0xFFFFFF;

        return $bucket < $this->sampleRate;
    }
}
