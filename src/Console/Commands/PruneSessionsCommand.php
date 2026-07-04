<?php

declare(strict_types=1);

namespace Padosoft\Iam\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Carbon;
use Padosoft\Iam\Domain\Identity\Models\Session;
use Padosoft\Iam\Domain\Identity\Session\NativeSessionRegistry;

/**
 * Session hygiene. Two steps: (1) mark idle- and absolute-expired sessions as revoked (with the reason), so
 * the store reflects reality instead of leaving dead sessions as `revoked_at = null`; (2) hard-delete rows
 * revoked longer than the retention window. Schedule it daily — without it `iam_sessions` grows unbounded.
 */
final class PruneSessionsCommand extends Command
{
    protected $signature = 'iam:prune-sessions {--days= : override retention days (default iam.authentication.session.retention_days)}';

    protected $description = 'Marca le sessioni idle/scadute come revocate ed elimina quelle revocate oltre la retention.';

    public function handle(NativeSessionRegistry $registry): int
    {
        $expired = $registry->expireInactive();

        $days = $this->option('days');
        $retention = is_string($days) && is_numeric($days) ? (int) $days : self::intConfig('iam.authentication.session.retention_days', 90);
        $cutoff = Carbon::now()->subDays(max(0, $retention));
        $stale = Session::query()->whereNotNull('revoked_at')->where('revoked_at', '<', $cutoff);
        $deleted = $stale->count();
        $stale->delete();

        $this->info("Prune sessioni: {$expired} marcate scadute, {$deleted} righe eliminate (retention {$retention}g).");

        return self::SUCCESS;
    }

    private static function intConfig(string $key, int $default): int
    {
        $value = config($key, $default);

        return is_numeric($value) ? (int) $value : $default;
    }
}
