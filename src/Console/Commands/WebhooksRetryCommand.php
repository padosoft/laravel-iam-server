<?php

declare(strict_types=1);

namespace Padosoft\Iam\Console\Commands;

use Illuminate\Console\Command;
use Padosoft\Iam\Domain\Audit\Webhooks\WebhookRetrier;

/**
 * Riconsegna le delivery webhook scadute (doc 12 §6): il push al momento della sigillatura
 * (AuditEventPusher, P2) fa UN tentativo; tutto ciò che finisce 'retrying' (5xx, timeout, worker
 * morto dopo il claim) viene ripreso da qui con backoff esponenziale, fino alla soglia → 'failed'
 * (DLQ). Schedulalo ogni minuto: senza, le delivery fallite restano ferme per sempre.
 */
final class WebhooksRetryCommand extends Command
{
    protected $signature = 'iam:webhooks-retry {--batch=100 : quante delivery scadute riprovare per invocazione}';

    protected $description = 'Riconsegna le delivery webhook in retrying con next_retry_at scaduto.';

    public function handle(WebhookRetrier $retrier): int
    {
        $batch = $this->option('batch');
        $batch = is_string($batch) && is_numeric($batch) && (int) $batch > 0 ? (int) $batch : 100;

        $retried = $retrier->retryDue($batch);

        $this->info("Webhook retry: {$retried} delivery riprovate (batch {$batch}).");

        return self::SUCCESS;
    }
}
