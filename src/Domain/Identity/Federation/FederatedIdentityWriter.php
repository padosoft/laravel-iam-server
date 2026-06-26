<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Identity\Federation;

use Padosoft\Iam\Domain\Identity\Models\FederatedIdentity;
use Padosoft\Iam\Domain\Identity\Models\FederatedProvider;

/**
 * Crea righe iam_federated_identities in modo controllato (user_id/status/linked_at sono fuori
 * da fillable). Un link `linked` ha un utente; un link `pending` no (richiede risoluzione).
 */
final class FederatedIdentityWriter
{
    public function write(
        FederatedProvider $provider,
        FederatedProfile $profile,
        ?string $userId,
        string $status,
        ?string $pendingReason,
    ): FederatedIdentity {
        $now = now();
        $identity = new FederatedIdentity;
        $identity->forceFill([
            'provider_id' => $provider->id,
            'provider_subject' => $profile->providerSubject,
            'user_id' => $userId,
            'status' => $status,
            'email' => $profile->normalizedEmail(),
            'email_verified' => $profile->emailVerified,
            'display_name' => $profile->displayName,
            'pending_reason' => $pendingReason,
            'linked_at' => $status === 'linked' ? $now : null,
            'last_login_at' => $status === 'linked' ? $now : null,
        ])->save();

        return $identity;
    }
}
