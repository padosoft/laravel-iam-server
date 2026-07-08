<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Identity\Assurance;

use Padosoft\Iam\Contracts\Assurance\Aal;
use Padosoft\Iam\Contracts\Assurance\AssuranceProvider;
use Padosoft\Iam\Contracts\Identity\SessionRef;
use Padosoft\Iam\Contracts\Identity\SessionRegistry;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Iam\Domain\Identity\Models\Session;

/**
 * AAL nativo: legge il livello dalla sessione attiva (Fortify TOTP + passkeys, doc 10 §4).
 * Una sessione non attiva vale AAL1 (fail-closed). aal3 è demandato a un adapter (Rebel/hardware).
 */
final class NativeAssuranceProvider implements AssuranceProvider
{
    public function __construct(private readonly SessionRegistry $sessions) {}

    public function currentAal(SubjectRef $subject, SessionRef $session): Aal
    {
        if (!$this->sessions->active($session->id)) {
            return Aal::AAL1;
        }
        $model = Session::query()->whereKey($session->id)->first();
        if ($model === null) {
            return Aal::AAL1;
        }

        $aal = Aal::fromString($model->aal);

        // IAM-19: freshness. An AAL above AAL1 comes from a step-up and is valid only for a bounded window.
        // Past it (or with no recorded step_up_at) the elevation has expired → fall back to AAL1 so a
        // requires_step_up action forces a FRESH step-up instead of trusting a stale hours-old elevation.
        if ($aal->rank() > Aal::AAL1->rank() && !$this->stepUpFresh($model)) {
            return Aal::AAL1;
        }

        return $aal;
    }

    private function stepUpFresh(Session $model): bool
    {
        $stepUpAt = $model->step_up_at;
        if ($stepUpAt === null) {
            return false;
        }
        $window = config('iam.authentication.session.step_up_freshness', 900);
        $window = is_numeric($window) ? (int) $window : 900;
        if ($window <= 0) {
            return true; // 0/negativo = freschezza disattivata (l'elevazione non scade)
        }

        return abs($stepUpAt->diffInSeconds(now())) <= $window;
    }

    public function supports(Aal $target): bool
    {
        // Native copre AAL1/AAL2 (password + TOTP/passkey); AAL3 (hardware/PSD2) → adapter.
        return $target->rank() <= Aal::AAL2->rank();
    }
}
