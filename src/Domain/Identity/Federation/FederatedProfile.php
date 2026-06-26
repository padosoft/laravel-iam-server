<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Identity\Federation;

/**
 * Profilo restituito da un IdP upstream (Socialite/OIDC). `providerSubject` è l'identificatore
 * stabile (sub), il legame primario dell'identità. `emailVerified` riflette se l'IdP ha
 * verificato l'email: è la condizione per l'auto-link (anti account-takeover, doc 10 §5).
 */
final readonly class FederatedProfile
{
    public function __construct(
        public string $providerSubject,
        public ?string $email = null,
        public bool $emailVerified = false,
        public ?string $displayName = null,
    ) {}

    /** Email normalizzata (lowercase, trim) o null. */
    public function normalizedEmail(): ?string
    {
        if ($this->email === null) {
            return null;
        }
        $email = strtolower(trim($this->email));

        return $email !== '' ? $email : null;
    }

    public function emailDomain(): ?string
    {
        $email = $this->normalizedEmail();
        if ($email === null) {
            return null;
        }
        $at = strrpos($email, '@');

        return $at !== false ? substr($email, $at + 1) : null;
    }
}
