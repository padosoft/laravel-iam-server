<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Governance\Reviews;

use Padosoft\Iam\Domain\Authorization\Models\Grant;
use Padosoft\Iam\Domain\Identity\Models\User;

/**
 * Calcola i "segnali smart" (doc 14 §3) che pre-istruiscono il reviewer e pre-evidenziano i
 * candidati alla revoca. Riusa la cattura `last_used_at` (§2) e lo stato dell'utente — lo stesso
 * investimento che alimenta il Least-privilege (§7). Lo snapshot viene congelato in
 * ReviewItem.signals_json al momento dell'apertura della campagna (storia immutabile).
 *
 * @phpstan-type Signals array{
 *     never_used: bool,
 *     dormant: bool,
 *     last_used_days: int|null,
 *     privileged: bool,
 *     subject_disabled: bool,
 * }
 */
final class ReviewSignals
{
    /**
     * @return Signals
     */
    public function for(Grant $grant): array
    {
        $unusedDays = $this->threshold('unused_days', 90);

        $lastUsedDays = null;
        $neverUsed = $grant->last_used_at === null;
        if ($grant->last_used_at !== null) {
            // diffInDays ritorna sempre >= 0 (valore assoluto): un grant usato nel futuro non esiste.
            $lastUsedDays = (int) $grant->last_used_at->diffInDays(now());
        }

        return [
            'never_used' => $neverUsed,
            'dormant' => $neverUsed || ($lastUsedDays !== null && $lastUsedDays >= $unusedDays),
            'last_used_days' => $lastUsedDays,
            'privileged' => $grant->is_privileged,
            'subject_disabled' => $this->subjectDisabled($grant),
        ];
    }

    /** Account a monte disabilitato (probabile cessazione): solo per soggetti `user` noti. */
    private function subjectDisabled(Grant $grant): bool
    {
        if ($grant->subject_type !== 'user') {
            return false;
        }
        $status = User::query()->whereKey($grant->subject_id)->value('status');

        return is_string($status) && $status !== 'active';
    }

    private function threshold(string $key, int $default): int
    {
        $value = config('iam-governance.least_privilege.'.$key, $default);

        return is_int($value) ? $value : $default;
    }
}
