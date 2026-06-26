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

        return $model !== null ? Aal::fromString($model->aal) : Aal::AAL1;
    }

    public function supports(Aal $target): bool
    {
        // Native copre AAL1/AAL2 (password + TOTP/passkey); AAL3 (hardware/PSD2) → adapter.
        return $target->rank() <= Aal::AAL2->rank();
    }
}
