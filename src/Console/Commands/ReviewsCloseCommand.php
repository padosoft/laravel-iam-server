<?php

declare(strict_types=1);

namespace Padosoft\Iam\Console\Commands;

use Illuminate\Console\Command;
use Padosoft\Iam\Domain\Governance\Reviews\CampaignEngine;
use Padosoft\Iam\Domain\Governance\Reviews\Models\ReviewCampaign;

/**
 * iam:reviews:close — chiude una campagna applicando on_unconfirmed (revoke|keep|suspend) ai soli
 * item ancora pending. Da schedulare a due_at per l'auto-revoca del non riconfermato (doc 14 §3).
 */
final class ReviewsCloseCommand extends Command
{
    protected $signature = 'iam:reviews:close {--campaign= : id della campagna da chiudere}';

    protected $description = 'Chiude una campagna di Access Review e applica l\'azione sui non confermati.';

    public function handle(CampaignEngine $engine): int
    {
        $id = $this->option('campaign');
        if (!is_string($id) || $id === '') {
            $this->error('Opzione --campaign mancante.');

            return self::FAILURE;
        }
        $campaign = ReviewCampaign::query()->find($id);
        if ($campaign === null) {
            $this->error("Campagna \"{$id}\" non trovata.");

            return self::FAILURE;
        }

        $processed = $engine->close($campaign);
        $this->info("Campagna \"{$campaign->name}\" chiusa: {$processed} item non confermati processati (on_unconfirmed={$campaign->on_unconfirmed}).");

        return self::SUCCESS;
    }
}
