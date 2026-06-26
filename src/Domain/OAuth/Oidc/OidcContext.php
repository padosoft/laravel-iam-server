<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\OAuth\Oidc;

use DateTimeImmutable;

/**
 * Trasporta i dati di autenticazione (nonce, auth_time, e dalla M5.4 la sessione: sid/acr/amr)
 * dentro la singola richiesta, dove league non lascia un canale:
 *  - in /authorize: l'AuthorizeController li imposta → l'AuthCodeRepository li persiste nell'auth code;
 *  - in /token: la ScopeRepository (che riceve authCodeId) li ripristina dal code → la response li
 *    inserisce nell'access token (sid) e nell'id_token (nonce/acr/amr/auth_time).
 *
 * Singleton di richiesta (PHP-FPM = un container per richiesta). Resettato a ogni richiesta token
 * dal TokenController per evitare residui sotto SAPI persistenti (Octane, vedi M14).
 */
final class OidcContext
{
    private ?string $nonce = null;

    private ?DateTimeImmutable $authTime = null;

    private ?string $sid = null;

    private ?string $acr = null;

    /** @var list<string> */
    private array $amr = [];

    public function set(?string $nonce, ?DateTimeImmutable $authTime): void
    {
        $this->nonce = ($nonce !== null && $nonce !== '') ? $nonce : null;
        $this->authTime = $authTime;
    }

    /**
     * Lega la sessione corrente (M5.1/M5.2) ai claim del token.
     *
     * @param  list<string>  $amr
     */
    public function setSession(?string $sid, ?string $acr, array $amr): void
    {
        $this->sid = ($sid !== null && $sid !== '') ? $sid : null;
        $this->acr = ($acr !== null && $acr !== '') ? $acr : null;
        $this->amr = array_values(array_filter($amr, static fn (string $m): bool => $m !== ''));
    }

    public function nonce(): ?string
    {
        return $this->nonce;
    }

    public function authTime(): ?DateTimeImmutable
    {
        return $this->authTime;
    }

    public function sid(): ?string
    {
        return $this->sid;
    }

    public function acr(): ?string
    {
        return $this->acr;
    }

    /** @return list<string> */
    public function amr(): array
    {
        return $this->amr;
    }

    public function reset(): void
    {
        $this->nonce = null;
        $this->authTime = null;
        $this->sid = null;
        $this->acr = null;
        $this->amr = [];
    }
}
