<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Identity\Federation;

use Illuminate\Support\Facades\DB;
use Padosoft\Iam\Domain\Authorization\Models\Grant;
use Padosoft\Iam\Domain\Identity\Models\FederatedProvider;
use Padosoft\Iam\Domain\Identity\Models\User;
use Padosoft\Iam\Domain\Organizations\Models\Membership;

/**
 * JIT provisioning (doc 10 §6): al primo login federato, se la policy lo consente, crea utente +
 * membership + ruoli bootstrap. Gate secure-by-default: richiede email verificata, opzionale
 * allowlist di domini, opzionale approval. Mai sovrascrivere un account con la stessa email.
 */
final class JitProvisioner
{
    public function __construct(private readonly FederatedIdentityWriter $writer) {}

    public function provision(FederatedProvider $provider, FederatedProfile $profile): LinkOutcome
    {
        $policy = is_array($provider->jit_policy) ? $provider->jit_policy : [];

        // Default sicuro: serve email verificata (un nuovo account su email non verificata
        // sarebbe squatting). Override solo esplicito via policy.
        if (($policy['require_verified_email'] ?? true) !== false && !$profile->emailVerified) {
            return $this->pending($provider, $profile, 'jit_requires_verified_email');
        }

        $allowed = $policy['allowed_domains'] ?? null;
        if (is_array($allowed) && $allowed !== []) {
            $domain = $profile->emailDomain();
            if ($domain === null || !in_array($domain, $allowed, true)) {
                return $this->pending($provider, $profile, 'jit_domain_not_allowed');
            }
        }

        if (($policy['approval_required'] ?? false) === true) {
            return $this->pending($provider, $profile, 'jit_approval_required');
        }

        $email = $profile->normalizedEmail();
        if ($email !== null && User::query()->where('email', $email)->exists()) {
            // Non creare un nuovo utente su un'email già presa (no takeover/squatting).
            return $this->pending($provider, $profile, 'email_taken');
        }

        $userId = '';
        $identityId = '';
        DB::transaction(function () use ($provider, $profile, $email, $policy, &$userId, &$identityId): void {
            $user = User::query()->create([
                'email' => $email,
                'name' => $profile->displayName,
                'email_verified_at' => $profile->emailVerified ? now() : null,
            ]);
            $userId = $user->id;

            if (is_string($provider->organization_id)) {
                Membership::query()->create([
                    'organization_id' => $provider->organization_id,
                    'user_id' => $user->id,
                    'source' => 'jit',
                    'joined_at' => now(),
                ]);
                foreach ($this->defaultRoles($policy) as $role) {
                    Grant::query()->create([
                        'organization_id' => $provider->organization_id,
                        'subject_type' => 'user',
                        'subject_id' => $user->id,
                        'privilege_type' => 'role',
                        'privilege_key' => $role,
                        'source' => 'jit',
                        'valid_from' => now(),
                    ]);
                }
            }

            $identityId = $this->writer->write($provider, $profile, $user->id, 'linked', null)->id;
        });

        return LinkOutcome::provisioned($userId, $identityId);
    }

    private function pending(FederatedProvider $provider, FederatedProfile $profile, string $reason): LinkOutcome
    {
        $identity = $this->writer->write($provider, $profile, null, 'pending', $reason);

        return LinkOutcome::pending($identity->id, $reason);
    }

    /**
     * @param  array<string, mixed>  $policy
     * @return list<string>
     */
    private function defaultRoles(array $policy): array
    {
        $roles = $policy['default_roles'] ?? [];

        return is_array($roles) ? array_values(array_filter($roles, 'is_string')) : [];
    }
}
