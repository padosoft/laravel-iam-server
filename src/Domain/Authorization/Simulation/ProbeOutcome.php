<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Authorization\Simulation;

use Padosoft\Iam\Domain\Authorization\Models\PolicyProbe;

/**
 * Cosa è successo a UNA sonda attraverso una modifica proposta.
 *
 * Le quattro combinazioni non sono simmetriche, ed è il motivo per cui il report
 * le tiene separate invece di contare "quante sono cambiate":
 *
 *  - **granted** (deny → allow) — qualcuno ha ottenuto autorità che non aveva.
 *    È la direzione che va guardata per prima, sempre.
 *  - **revoked** (allow → deny) — qualcuno perde autorità. Rompe le persone,
 *    non la sicurezza: è un incidente diverso e va letto diversamente.
 *  - **unchanged** — la maggioranza, e la ragione per cui un report utile deve
 *    poterla nascondere.
 *  - **step-up appeared/disappeared** — la decisione non cambia ma il costo per
 *    l'utente sì; contarla come "invariata" nasconderebbe una regressione UX
 *    reale.
 */
final readonly class ProbeOutcome
{
    public const GRANTED = 'granted';

    public const REVOKED = 'revoked';

    public const UNCHANGED = 'unchanged';

    public const STEP_UP_ADDED = 'step_up_added';

    public const STEP_UP_REMOVED = 'step_up_removed';

    /**
     * @param  list<string>  $explanationAfter
     */
    public function __construct(
        public PolicyProbe $probe,
        public bool $before,
        public bool $after,
        public bool $stepUpBefore,
        public bool $stepUpAfter,
        public array $explanationAfter = [],
    ) {}

    public function kind(): string
    {
        if ($this->before !== $this->after) {
            return $this->after ? self::GRANTED : self::REVOKED;
        }

        if ($this->stepUpBefore !== $this->stepUpAfter) {
            return $this->stepUpAfter ? self::STEP_UP_ADDED : self::STEP_UP_REMOVED;
        }

        return self::UNCHANGED;
    }

    public function changed(): bool
    {
        return $this->kind() !== self::UNCHANGED;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            ...$this->probe->describe(),
            'kind' => $this->kind(),
            'before' => $this->before,
            'after' => $this->after,
            'step_up_before' => $this->stepUpBefore,
            'step_up_after' => $this->stepUpAfter,
            // La spiegazione DOPO, non prima: quando una decisione ribalta la
            // domanda è sempre "perché adesso sì/no", e lo stato di arrivo è
            // quello che la risponde.
            'explanation_after' => $this->explanationAfter,
        ];
    }
}
