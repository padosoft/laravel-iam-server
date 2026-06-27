<?php

declare(strict_types=1);

namespace Padosoft\Iam\Observability;

/**
 * Astrazione di tracing/telemetria (M14, OTEL). Il control plane emette span attorno alle operazioni
 * critiche (decisioni PDP, firma token, sync) ed eventi di errore; l'esportazione concreta (OTLP,
 * ELK, log) è un dettaglio del driver. Default `NullTracer` (nessuna dipendenza pesante); un'app può
 * bindare un esportatore OTLP reale. Il tracing NON deve mai alterare il risultato di business: lo
 * span avvolge il callback e ne restituisce il valore, propagando eventuali eccezioni dopo averle
 * registrate.
 */
interface Tracer
{
    /**
     * Avvolge $callback in uno span. Ritorna il valore del callback; se lancia, registra l'errore e
     * ri-lancia (il tracing non inghiotte mai un'eccezione di business).
     *
     * @template T
     *
     * @param  callable(): T  $callback
     * @param  array<string, scalar|null>  $attributes
     * @return T
     */
    public function span(string $name, callable $callback, array $attributes = []): mixed;

    /** @param array<string, scalar|null> $attributes */
    public function event(string $name, array $attributes = []): void;

    /** @param array<string, scalar|null> $attributes */
    public function recordError(\Throwable $error, array $attributes = []): void;
}
