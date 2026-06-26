<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Identity\Assurance;

use Padosoft\Iam\Contracts\Assurance\FactorVerifier;
use Padosoft\Iam\Contracts\Support\SubjectRef;

/**
 * FactorVerifier di default fail-closed: nega ogni verifica finché un verifier reale
 * (Fortify TOTP / laravel-passkeys, cablato in M5.4, o un adapter Rebel) non è bindato.
 * Così uno step-up non può MAI riuscire per assenza di configurazione.
 */
final class UnconfiguredFactorVerifier implements FactorVerifier
{
    public function verify(SubjectRef $subject, array $payload): bool
    {
        return false;
    }
}
