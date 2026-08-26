<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Authorization\Simulation;

use RuntimeException;

/**
 * Segnale interno: la simulazione ha finito di misurare e la transazione deve
 * tornare indietro.
 *
 * È un'eccezione e non un flag perché è l'unico modo di uscire da
 * `DB::transaction()` senza committare. Non esce mai da
 * {@see BlastRadiusSimulator}: se la si vede risalire, la simulazione ha un bug
 * e — più importante — potrebbe aver committato.
 *
 * @internal
 */
final class SimulationRollback extends RuntimeException {}
