<?php

declare(strict_types=1);

namespace Padosoft\Iam\Console\Commands;

use Illuminate\Console\Command;
use Padosoft\Iam\Domain\Governance\Reviews\CampaignEngine;
use Padosoft\Iam\Domain\Governance\Reviews\Models\ReviewCampaign;

/**
 * iam:reviews:open — apre una campagna di Access Review: genera gli item da certificare con i
 * segnali smart e la porta in stato `running` (doc 14 §3).
 */
final class ReviewsOpenCommand extends Command
{
    protected $signature = 'iam:reviews:open {--campaign= : id della campagna da aprire}';

    protected $description = 'Apre una campagna di Access Review e genera gli item da certificare.';

    public function handle(CampaignEngine $engine): int
    {
        $campaign = $this->resolveCampaign();
        if ($campaign === null) {
            return self::FAILURE;
        }

        $created = $engine->open($campaign);
        $this->info("Campagna \"{$campaign->name}\" aperta: {$created} accessi da certificare.");

        return self::SUCCESS;
    }

    private function resolveCampaign(): ?ReviewCampaign
    {
        $id = $this->option('campaign');
        if (!is_string($id) || $id === '') {
            $this->error('Opzione --campaign mancante.');

            return null;
        }
        $campaign = ReviewCampaign::query()->find($id);
        if ($campaign === null) {
            $this->error("Campagna \"{$id}\" non trovata.");

            return null;
        }

        return $campaign;
    }
}
