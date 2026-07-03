<?php

declare(strict_types=1);

namespace Padosoft\Iam\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Database\Eloquent\Collection;
use Padosoft\Iam\Domain\OAuth\Models\OauthClient;

/**
 * Auto-rotation (doc 13 §4.2). Scheduled: rotates the secret of every confidential client that opted into
 * `auto_rotate` and whose interval has elapsed, storing the new secret ENCRYPTED for the app to self-fetch
 * during the grace; and clears pending ciphertexts whose grace has already lapsed. No human in the loop.
 */
final class RotateDueSecretsCommand extends Command
{
    protected $signature = 'iam:rotate-due-secrets';

    protected $description = 'Ruota i secret dei client OAuth con auto-rotazione dovuta; azzera i pending il cui grace è scaduto.';

    public function handle(): int
    {
        $grace = self::intConfig('iam.oauth.client_secret_grace', 259200);
        $ttlCfg = config('iam.oauth.client_secret_ttl');
        $ttl = is_numeric($ttlCfg) && (int) $ttlCfg > 0 ? (int) $ttlCfg : null;

        $rotated = 0;
        $cleared = 0;
        OauthClient::query()
            ->where('is_confidential', true)->whereNull('revoked_at')
            ->where(fn ($q) => $q->where('auto_rotate', true)->orWhereNotNull('secret_pending_encrypted'))
            ->chunkById(200, function (Collection $clients) use ($grace, $ttl, &$rotated, &$cleared): void {
                foreach ($clients as $client) {
                    if (!$client instanceof OauthClient) {
                        continue;
                    }
                    // Il pending di una rotazione il cui grace è scaduto non serve più (l'app ha avuto tempo).
                    if ($client->secret_pending_encrypted !== null && !$client->previousSecretActive()) {
                        $client->clearPendingSecret();
                        $cleared++;
                    }
                    if ($client->dueForRotation()) {
                        $client->rotateSecret($grace, $ttl, storeForPickup: true);
                        $rotated++;
                    }
                }
            });

        $this->info("Auto-rotation: {$rotated} ruotati, {$cleared} pending azzerati.");

        return self::SUCCESS;
    }

    private static function intConfig(string $key, int $default): int
    {
        $value = config($key, $default);

        return is_numeric($value) ? (int) $value : $default;
    }
}
