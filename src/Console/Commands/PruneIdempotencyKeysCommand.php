<?php

declare(strict_types=1);

namespace Padosoft\Iam\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;

/**
 * Igiene dello store di idempotency (IAM-08). Le righe di `iam_idempotency_keys` non hanno una scadenza
 * naturale: senza prune crescerebbero all'infinito. Elimina le righe più vecchie della retention (default
 * 7 giorni: ben oltre ogni finestra di retry realistica). Schedulalo giornaliero.
 */
final class PruneIdempotencyKeysCommand extends Command
{
    protected $signature = 'iam:prune-idempotency {--days= : override retention days (default iam.admin.idempotency_retention_days)}';

    protected $description = 'Elimina le chiavi di idempotency più vecchie della retention.';

    public function handle(): int
    {
        $days = $this->option('days');
        $retention = is_string($days) && is_numeric($days)
            ? (int) $days
            : self::intConfig('iam.admin.idempotency_retention_days', 7);
        $cutoff = Carbon::now()->subDays(max(0, $retention));

        $deleted = DB::table('iam_idempotency_keys')->where('created_at', '<', $cutoff)->delete();

        $this->info("Prune idempotency: {$deleted} righe eliminate (retention {$retention}g).");

        return self::SUCCESS;
    }

    private static function intConfig(string $key, int $default): int
    {
        $value = config($key, $default);

        return is_numeric($value) ? (int) $value : $default;
    }
}
