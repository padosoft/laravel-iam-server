<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Identity\Federation;

use Padosoft\Iam\Domain\Identity\Models\FederatedIdentity;
use Padosoft\Iam\Domain\Identity\Models\FederatedProvider;
use Padosoft\Iam\Domain\Identity\Models\User;

/**
 * Risoluzione/linking di un'identità federata al login (doc 10 §5). Invarianti non negoziabili:
 *  - la verità è (provider, provider_subject), MAI la sola email;
 *  - l'auto-link a un account ESISTENTE avviene SOLO con email verificata dall'IdP (anti
 *    account-takeover): altrimenti JIT (nuovo utente isolato) o pending;
 *  - ogni conflitto (email dell'utente già legata a un subject diverso) → pending, mai silenzioso.
 */
final class AccountLinker
{
    public function __construct(
        private readonly JitProvisioner $jit,
        private readonly FederatedIdentityWriter $writer,
    ) {}

    public function resolve(FederatedProvider $provider, FederatedProfile $profile): LinkOutcome
    {
        if ($profile->providerSubject === '') {
            throw new \InvalidArgumentException('provider_subject mancante.');
        }

        // 1. Link esistente per (provider, provider_subject): è la fonte di verità dell'identità.
        $existing = FederatedIdentity::query()
            ->where('provider_id', $provider->id)
            ->where('provider_subject', $profile->providerSubject)
            ->whereNull('revoked_at')
            ->first();
        if ($existing !== null) {
            if ($existing->status === 'linked' && is_string($existing->user_id) && $existing->user_id !== '') {
                $userId = $existing->user_id;
                $existing->forceFill(['last_login_at' => now()])->save();

                return LinkOutcome::linked($userId, $existing->id);
            }

            return LinkOutcome::pending($existing->id, $existing->pending_reason ?? 'link_pending');
        }

        // 2. Auto-link a un account esistente: SOLO con email verificata + policy del provider.
        $email = $profile->normalizedEmail();
        $canAutoLink = $profile->emailVerified && $email !== null && $provider->auto_link_policy === 'verified_email';
        if (!$canAutoLink) {
            // Nessun auto-link su email non verificata: JIT (nuovo utente) o pending via policy JIT.
            return $this->jit->provision($provider, $profile);
        }

        // 3. Email verificata: nessun utente con quell'email → JIT; esiste → auto-link salvo conflitto.
        $emailUser = User::query()->where('email', $email)->first();
        if ($emailUser === null) {
            return $this->jit->provision($provider, $profile);
        }

        $conflict = FederatedIdentity::query()
            ->where('provider_id', $provider->id)
            ->where('user_id', $emailUser->id)
            ->where('provider_subject', '!=', $profile->providerSubject)
            ->whereNull('revoked_at')
            ->exists();
        if ($conflict) {
            $identity = $this->writer->write($provider, $profile, null, 'pending', 'email_conflict');

            return LinkOutcome::pending($identity->id, 'email_conflict');
        }

        $identity = $this->writer->write($provider, $profile, $emailUser->id, 'linked', null);

        return LinkOutcome::linked($emailUser->id, $identity->id);
    }
}
