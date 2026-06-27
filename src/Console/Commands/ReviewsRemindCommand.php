<?php

declare(strict_types=1);

namespace Padosoft\Iam\Console\Commands;

use Illuminate\Console\Command;
use Padosoft\Iam\Domain\Governance\Reviews\CampaignEngine;
use Padosoft\Iam\Domain\Governance\Reviews\Models\ReviewCampaign;

/**
 * iam:reviews:remind — elenca i reviewer con item ancora pending in una campagna, così da poterli
 * sollecitare (email/webhook/in-app sono cablati lato notifiche/web panel — doc 14 §3 / doc 16).
 */
final class ReviewsRemindCommand extends Command
{
    protected $signature = 'iam:reviews:remind {--campaign= : id della campagna}';

    protected $description = 'Elenca i reviewer ancora da sollecitare (item pending) di una campagna.';

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

        $reviewers = $engine->remind($campaign);
        if ($reviewers === []) {
            $this->info("Campagna \"{$campaign->name}\": nessun reviewer pendente.");

            return self::SUCCESS;
        }

        $this->info("Campagna \"{$campaign->name}\": ".count($reviewers).' reviewer da sollecitare.');
        foreach ($reviewers as $reviewer) {
            $this->line("  - {$reviewer}");
        }

        return self::SUCCESS;
    }
}
