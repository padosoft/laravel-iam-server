<?php

declare(strict_types=1);

namespace Padosoft\Iam\Observability;

/**
 * Composite tracer (M14): fans every span/event/error out to several tracers at once — e.g. `log`
 * (structured local logs) AND `otlp` (push to the collector). Wired by `IAM_TRACER=stack`.
 *
 * `span()` must return the callback's value exactly once, so the wrapped tracers are chained: the
 * innermost runs the real callback, each outer one wraps it. Business behaviour and exceptions are
 * preserved; a tracer that only observes never alters the result.
 */
final class StackTracer implements Tracer
{
    /** @var list<Tracer> */
    private readonly array $tracers;

    public function __construct(Tracer ...$tracers)
    {
        $this->tracers = array_values($tracers);
    }

    public function span(string $name, callable $callback, array $attributes = []): mixed
    {
        // Nest the tracers so the callback runs once; the value/exception propagate through each layer.
        $wrapped = $callback;
        foreach ($this->tracers as $tracer) {
            $inner = $wrapped;
            $wrapped = static fn () => $tracer->span($name, $inner, $attributes);
        }

        return $wrapped();
    }

    public function event(string $name, array $attributes = []): void
    {
        foreach ($this->tracers as $tracer) {
            $tracer->event($name, $attributes);
        }
    }

    public function recordError(\Throwable $error, array $attributes = []): void
    {
        foreach ($this->tracers as $tracer) {
            $tracer->recordError($error, $attributes);
        }
    }

    /** Flush any child tracer that buffers (e.g. the OTLP exporter). */
    public function flush(): void
    {
        foreach ($this->tracers as $tracer) {
            if ($tracer instanceof OtlpTracer) {
                $tracer->flush();
            }
        }
    }
}
