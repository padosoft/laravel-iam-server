<?php

declare(strict_types=1);

namespace Padosoft\Iam\Console\Commands;

use Illuminate\Console\Command;
use Padosoft\Iam\Domain\Authorization\Models\PolicyProbe;
use Padosoft\Iam\Domain\Authorization\Simulation\PolicyRegressionRunner;

/**
 * `iam:policy:check` — il gate di CI.
 *
 * Valuta le sonde che portano un esito atteso contro lo stato corrente della
 * policy ed esce non-zero alla prima divergenza. È il posto in cui si scopre che
 * "il CFO non legge più payroll" **prima** che lo scopra il CFO.
 *
 * Un corpus vuoto — o pieno di sonde senza aspettativa — esce ZERO ma lo dice a
 * voce alta: un gate che passa perché non ha niente da controllare è peggio di
 * nessun gate, perché sembra uno.
 */
final class PolicyCheckCommand extends Command
{
    protected $signature = 'iam:policy:check {--org= : limita a un\'organizzazione} {--json : output JSON}';

    protected $description = 'Valuta il corpus di regressione della policy contro lo stato corrente; esce non-zero su divergenze.';

    public function handle(PolicyRegressionRunner $runner): int
    {
        $org = $this->option('org');

        $query = PolicyProbe::query()->orderBy('id');

        if (is_string($org) && $org !== '') {
            $query->where('organization_id', $org);
        }

        /** @var list<PolicyProbe> $probes */
        $probes = array_values($query->get()->all());

        $result = $runner->run($probes);

        if ((bool) $this->option('json')) {
            $this->line((string) json_encode($result->toArray(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

            return $result->passed() ? self::SUCCESS : self::FAILURE;
        }

        if ($result->checked === 0) {
            $this->warn('Nessuna sonda con un esito atteso: questo gate non sta controllando niente.');
            $this->line('  Aggiungi `expected_allowed` alle sonde che contano (POST /policy/probes) — un gate che passa a vuoto sembra un gate.');

            return self::SUCCESS;
        }

        if ($result->passed()) {
            $this->info(sprintf(
                '%d sonda/e verificata/e, nessuna divergenza (%d senza esito atteso, ignorate).',
                $result->checked,
                $result->skipped,
            ));

            return self::SUCCESS;
        }

        $this->error(sprintf('%d divergenza/e su %d sonda/e verificata/e:', count($result->failures), $result->checked));

        foreach ($result->failures as $failure) {
            $this->line(sprintf(
                '  - %s → %s%s: atteso %s, ottenuto %s',
                $failure['subject'],
                $failure['permission'],
                $failure['resource'] !== null ? ' on '.$failure['resource'] : '',
                $failure['expected_allowed'] === true ? 'allow' : 'deny',
                $failure['actual_allowed'] ? 'allow' : 'deny',
            ));

            foreach ($failure['explanation'] as $line) {
                $this->line('      '.$line);
            }
        }

        return self::FAILURE;
    }
}
