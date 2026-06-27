<?php

declare(strict_types=1);

namespace Padosoft\Iam\Observability;

/**
 * Tracer di default: nessuna esportazione, zero dipendenze. Esegue comunque il callback dello span
 * (il tracing non deve mai cambiare il comportamento) e ignora eventi/errori. È ciò che gira finché
 * un'app non bind a un esportatore reale (OTLP/ELK).
 */
final class NullTracer implements Tracer
{
    public function span(string $name, callable $callback, array $attributes = []): mixed
    {
        return $callback();
    }

    public function event(string $name, array $attributes = []): void {}

    public function recordError(\Throwable $error, array $attributes = []): void {}
}
