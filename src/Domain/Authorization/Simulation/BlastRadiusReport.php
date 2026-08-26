<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Authorization\Simulation;

/**
 * Il risultato di una simulazione: quante decisioni cambiano, in che direzione,
 * e quali.
 *
 * Il report NON è un verdetto. Non dice "questo cambio è sicuro": dice cosa
 * farebbe, contro il corpus di sonde che qualcuno ha scelto. Un blast radius di
 * zero su dieci sonde significa che quelle dieci non cambiano — non che nulla
 * cambia. La `coverage` è lì per rendere quel limite visibile, invece di
 * lasciare che un numero rassicurante venga letto come una garanzia.
 */
final readonly class BlastRadiusReport
{
    /**
     * @param  list<ProbeOutcome>  $outcomes
     */
    public function __construct(public array $outcomes) {}

    /**
     * @return list<ProbeOutcome>
     */
    public function changed(): array
    {
        return array_values(array_filter($this->outcomes, static fn (ProbeOutcome $o): bool => $o->changed()));
    }

    /**
     * @return list<ProbeOutcome>
     */
    public function ofKind(string $kind): array
    {
        return array_values(array_filter($this->outcomes, static fn (ProbeOutcome $o): bool => $o->kind() === $kind));
    }

    /**
     * @return array<string, int>
     */
    public function counts(): array
    {
        $counts = [
            ProbeOutcome::GRANTED => 0,
            ProbeOutcome::REVOKED => 0,
            ProbeOutcome::STEP_UP_ADDED => 0,
            ProbeOutcome::STEP_UP_REMOVED => 0,
            ProbeOutcome::UNCHANGED => 0,
        ];

        foreach ($this->outcomes as $outcome) {
            $counts[$outcome->kind()]++;
        }

        return $counts;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(bool $includeUnchanged = false): array
    {
        $rows = $includeUnchanged ? $this->outcomes : $this->changed();

        return [
            'probes' => count($this->outcomes),
            'counts' => $this->counts(),
            'coverage' => [
                'probes_evaluated' => count($this->outcomes),
                // Detto esplicitamente perché è l'unico modo di impedire che
                // "0 cambiamenti" venga letto come "nessun rischio".
                'note' => 'A blast radius is measured against these probes only. Zero changes here means these probes do not change — not that nothing does.',
            ],
            'changes' => array_map(static fn (ProbeOutcome $o): array => $o->toArray(), $rows),
        ];
    }
}
