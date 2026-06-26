<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\OAuth\Oidc;

use Padosoft\Iam\Domain\Identity\Models\User;

/**
 * Mappa scope OIDC → claim del subject (doc 13 §4/§5). Solo i claim coperti dagli scope
 * concessi vengono esposti (minimizzazione).
 */
final class ClaimExtractor
{
    /**
     * @param  list<string>  $scopes
     * @return array<string, mixed>
     */
    public function forUser(User $user, array $scopes): array
    {
        $claims = ['sub' => $user->id];

        if (in_array('profile', $scopes, true) && is_string($user->name) && $user->name !== '') {
            $claims['name'] = $user->name;
        }

        if (in_array('email', $scopes, true) && is_string($user->email) && $user->email !== '') {
            $claims['email'] = $user->email;
            $claims['email_verified'] = $user->email_verified_at !== null;
        }

        return $claims;
    }
}
