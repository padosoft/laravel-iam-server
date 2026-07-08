<?php

declare(strict_types=1);

namespace Padosoft\Iam\Observability;

use Psr\Log\LoggerInterface;

/**
 * Esportatore di telemetria su log strutturato (M14): span (con durata in ms), eventi ed errori
 * diventano righe JSON su un canale dedicato, che un collector (OTel Collector / Filebeat → ELK)
 * spedisce verso il backend. È l'approccio 12-factor "log = stream di eventi", senza cablare l'SDK
 * OTLP pesante nel core. Lo span resta trasparente al business: misura, registra, ri-lancia.
 */
final class LogTracer implements Tracer
{
    public function __construct(private readonly LoggerInterface $logger) {}

    public function span(string $name, callable $callback, array $attributes = []): mixed
    {
        $start = hrtime(true);
        try {
            $result = $callback();
            $this->logger->info('iam.span', $this->payload($name, $start, $attributes, 'ok'));

            return $result;
        } catch (\Throwable $e) {
            $this->logger->error('iam.span', $this->payload($name, $start, $attributes, 'error') + [
                'error_type' => $e::class,
            ]);

            throw $e; // mai inghiottire: il tracing osserva, non altera il flusso
        }
    }

    public function event(string $name, array $attributes = []): void
    {
        $this->logger->info('iam.event', ['event' => $name] + $this->scalarize($attributes));
    }

    public function recordError(\Throwable $error, array $attributes = []): void
    {
        // IAM-44: log the exception CLASS, never getMessage() — the message can carry secrets/PII on some
        // paths (tokens, decrypted values). Consistent with the rest of the codebase (e.g. HttpDecider).
        $this->logger->error('iam.error', [
            'error_type' => $error::class,
        ] + $this->scalarize($attributes));
    }

    /**
     * @param  array<string, scalar|null>  $attributes
     * @return array<string, scalar|null>
     */
    private function payload(string $name, int $start, array $attributes, string $status): array
    {
        return [
            'span' => $name,
            'status' => $status,
            'duration_ms' => (int) ((hrtime(true) - $start) / 1_000_000),
        ] + $this->scalarize($attributes);
    }

    /**
     * @param  array<string, scalar|null>  $attributes
     * @return array<string, scalar|null>
     */
    private function scalarize(array $attributes): array
    {
        $out = [];
        foreach ($attributes as $key => $value) {
            $out['attr_'.$key] = $value;
        }

        return $out;
    }
}
