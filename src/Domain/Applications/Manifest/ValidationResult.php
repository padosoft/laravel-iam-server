<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Applications\Manifest;

/**
 * Esito della validazione di un manifest: valido oppure lista di errori leggibili.
 */
final readonly class ValidationResult
{
    /** @param list<string> $errors */
    private function __construct(
        public bool $valid,
        public array $errors,
    ) {}

    public static function ok(): self
    {
        return new self(true, []);
    }

    /** @param list<string> $errors */
    public static function fail(array $errors): self
    {
        // fail() è SEMPRE invalido (anche con lista vuota): evita falsi "validated".
        return new self(false, array_values($errors));
    }
}
