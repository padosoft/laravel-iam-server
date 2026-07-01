<?php

declare(strict_types=1);

namespace Padosoft\Iam\Observability;

use Illuminate\Support\Facades\Http;

/**
 * Native OTLP/HTTP (JSON) tracer (M14): exports spans directly to an OpenTelemetry collector's
 * `POST {endpoint}/v1/traces`, no heavy OTEL SDK and no gRPC required. Spans are buffered in-memory
 * during the request and flushed in a single batch at the end (register the flush on `app terminating`),
 * so tracing never adds a network round-trip to the hot path (e.g. a PDP decision). Fail-open by
 * construction: any export error is swallowed — telemetry must never break business or leak an error.
 *
 * Only OTLP/HTTP with JSON encoding is implemented (the collector accepts it on port 4318). For gRPC
 * (4317) put the collector's HTTP endpoint here, or run behind a sidecar.
 */
final class OtlpTracer implements Tracer
{
    /** One trace id per tracer instance (i.e. per request, since it's request-singleton). */
    private readonly string $traceId;

    /** @var list<array<string, mixed>> */
    private array $spans = [];

    public function __construct(
        private readonly string $endpoint,
        private readonly string $serviceName,
        private readonly int $timeout = 5,
    ) {
        $this->traceId = bin2hex(random_bytes(16));
    }

    public function span(string $name, callable $callback, array $attributes = []): mixed
    {
        $spanId = bin2hex(random_bytes(8));
        $start = $this->nowNano();
        try {
            $result = $callback();
            $this->record($name, $spanId, $start, $attributes, statusCode: 1);

            return $result;
        } catch (\Throwable $e) {
            $this->record($name, $spanId, $start, $attributes + ['error_type' => $e::class], statusCode: 2, message: $e->getMessage());

            throw $e; // never swallow a business exception
        }
    }

    public function event(string $name, array $attributes = []): void
    {
        $now = $this->nowNano();
        $this->record($name, bin2hex(random_bytes(8)), $now, $attributes, statusCode: 0, end: $now);
    }

    public function recordError(\Throwable $error, array $attributes = []): void
    {
        $now = $this->nowNano();
        $this->record(
            'iam.error',
            bin2hex(random_bytes(8)),
            $now,
            $attributes + ['error_type' => $error::class],
            statusCode: 2,
            end: $now,
            message: $error->getMessage(),
        );
    }

    /**
     * Send the buffered spans to the collector as one OTLP/HTTP JSON batch. Best-effort: swallow any
     * transport error. Call from `app()->terminating(...)`.
     */
    public function flush(): void
    {
        if ($this->spans === []) {
            return;
        }

        $payload = [
            'resourceSpans' => [[
                'resource' => [
                    'attributes' => [self::attr('service.name', $this->serviceName)],
                ],
                'scopeSpans' => [[
                    'scope' => ['name' => 'laravel-iam'],
                    'spans' => $this->spans,
                ]],
            ]],
        ];

        $this->spans = [];

        try {
            Http::timeout($this->timeout)
                ->asJson()
                ->post(rtrim($this->endpoint, '/').'/v1/traces', $payload);
        } catch (\Throwable) {
            // telemetry is fire-and-forget; a down collector must not affect the app.
        }
    }

    /**
     * @param  array<string, scalar|null>  $attributes
     */
    private function record(string $name, string $spanId, int $start, array $attributes, int $statusCode, ?int $end = null, ?string $message = null): void
    {
        $span = [
            'traceId' => $this->traceId,
            'spanId' => $spanId,
            'name' => $name,
            'kind' => 1, // SPAN_KIND_INTERNAL
            'startTimeUnixNano' => (string) $start,
            'endTimeUnixNano' => (string) ($end ?? $this->nowNano()),
            'attributes' => array_map(
                static fn ($k, $v) => self::attr((string) $k, $v),
                array_keys($attributes),
                array_values($attributes),
            ),
            'status' => $message !== null
                ? ['code' => $statusCode, 'message' => $message]
                : ['code' => $statusCode],
        ];

        $this->spans[] = $span;
    }

    /**
     * @param  scalar|null  $value
     * @return array{key: string, value: array<string, mixed>}
     */
    private static function attr(string $key, $value): array
    {
        $typed = match (true) {
            is_bool($value) => ['boolValue' => $value],
            is_int($value) => ['intValue' => (string) $value],
            is_float($value) => ['doubleValue' => $value],
            $value === null => ['stringValue' => ''],
            default => ['stringValue' => (string) $value],
        };

        return ['key' => $key, 'value' => $typed];
    }

    private function nowNano(): int
    {
        return (int) (microtime(true) * 1_000_000_000);
    }
}
