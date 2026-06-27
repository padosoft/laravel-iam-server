<?php

declare(strict_types=1);

namespace Padosoft\Iam\Console\Commands;

use Illuminate\Console\Command;
use Padosoft\Iam\Domain\Governance\Recommendations\LeastPrivilegeRecommender;

/**
 * iam:least-privilege:scan — esegue il recommender deterministico (doc 14 §7) e stampa le
 * raccomandazioni DRAFT (proposte, mai azioni). `--org` limita lo scope; `--json` per pipeline.
 */
final class LeastPrivilegeScanCommand extends Command
{
    protected $signature = 'iam:least-privilege:scan {--org= : limita a un\'organizzazione} {--json : output JSON}';

    protected $description = 'Analizza grant/ruoli e propone azioni di least-privilege (solo draft).';

    public function handle(LeastPrivilegeRecommender $recommender): int
    {
        $org = $this->option('org');
        $recommendations = $recommender->analyze(is_string($org) && $org !== '' ? $org : null);

        if ((bool) $this->option('json')) {
            $this->line((string) json_encode(array_map(fn ($r) => $r->toArray(), $recommendations), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

            return self::SUCCESS;
        }

        if ($recommendations === []) {
            $this->info('Nessuna raccomandazione: gli accessi analizzati sono già minimi.');

            return self::SUCCESS;
        }

        $this->info(count($recommendations).' raccomandazioni (draft):');
        $this->table(
            ['Tipo', 'Severità', 'Azione', 'Target', 'Soggetto', 'Dettaglio'],
            array_map(fn ($r) => [$r->type, $r->severity, $r->recommendation, $r->targetRef, $r->subject ?? '—', $r->detail], $recommendations),
        );

        return self::SUCCESS;
    }
}
