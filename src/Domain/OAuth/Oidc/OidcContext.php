<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\OAuth\Oidc;

use DateTimeImmutable;

/**
 * Trasporta nonce e auth_time OIDC dentro la singola richiesta, dove league non lascia un canale:
 *  - in /authorize: l'AuthorizeController li imposta → l'AuthCodeRepository li persiste nell'auth code;
 *  - in /token: la ScopeRepository (che riceve authCodeId) li ripristina dal code → la response li
 *    inserisce nell'id_token.
 *
 * Singleton di richiesta (PHP-FPM = un container per richiesta). Resettato a ogni richiesta token
 * dal TokenController per evitare residui sotto SAPI persistenti (Octane, vedi M14).
 */
final class OidcContext
{
    private ?string $nonce = null;

    private ?DateTimeImmutable $authTime = null;

    public function set(?string $nonce, ?DateTimeImmutable $authTime): void
    {
        $this->nonce = ($nonce !== null && $nonce !== '') ? $nonce : null;
        $this->authTime = $authTime;
    }

    public function nonce(): ?string
    {
        return $this->nonce;
    }

    public function authTime(): ?DateTimeImmutable
    {
        return $this->authTime;
    }

    public function reset(): void
    {
        $this->nonce = null;
        $this->authTime = null;
    }
}
