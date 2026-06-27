<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Audit\Pii;

/**
 * Sollevata quando si tenta il crypto-shredding di un soggetto sotto legal hold attivo (doc 12 §7).
 */
final class LegalHoldActive extends \RuntimeException
{
    public static function for(string $subject): self
    {
        return new self("Crypto-shredding bloccato: il soggetto \"{$subject}\" è sotto legal hold attivo.");
    }
}
