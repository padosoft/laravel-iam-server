<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\OAuth;

use Defuse\Crypto\Crypto;

/**
 * Decifra il refresh token opaco emesso da league (cifrato con la encryptionKey via Defuse,
 * stesso formato di CryptTrait) per estrarne il refresh_token_id, così la revocation può
 * agire sul ledger/catena senza dipendere dalla state-machine del grant.
 */
final class RefreshTokenCrypto
{
    public function __construct(private readonly string $encryptionKey) {}

    /** Ritorna il refresh_token_id se il token è decifrabile e valido, altrimenti null. */
    public function refreshTokenId(string $encrypted): ?string
    {
        if ($encrypted === '') {
            return null;
        }
        try {
            $json = Crypto::decryptWithPassword($encrypted, $this->encryptionKey);
            $data = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        } catch (\Throwable) {
            return null;
        }

        $id = is_array($data) ? ($data['refresh_token_id'] ?? null) : null;

        return is_string($id) && $id !== '' ? $id : null;
    }
}
