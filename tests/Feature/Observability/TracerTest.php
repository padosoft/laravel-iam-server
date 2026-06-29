<?php

declare(strict_types=1);

use Padosoft\Iam\Observability\LogTracer;
use Padosoft\Iam\Observability\NullTracer;
use Psr\Log\AbstractLogger;

/** Logger PSR che accumula i record in memoria per l'asserzione. */
function recordingLogger(): AbstractLogger
{
    return new class extends AbstractLogger
    {
        /** @var list<array{level: mixed, message: string, context: array<string, mixed>}> */
        public array $records = [];

        public function log($level, $message, array $context = []): void
        {
            $this->records[] = ['level' => $level, 'message' => (string) $message, 'context' => $context];
        }
    };
}

it('NullTracer esegue il callback e ritorna il valore, ignorando eventi/errori', function () {
    $tracer = new NullTracer;

    expect($tracer->span('pdp.check', fn (): int => 42))->toBe(42);

    // event/recordError sono no-op: non devono lanciare.
    $tracer->event('x');
    $tracer->recordError(new RuntimeException('y'));
    expect(true)->toBeTrue();
});

it('NullTracer non inghiotte le eccezioni del callback', function () {
    $tracer = new NullTracer;

    expect(fn () => $tracer->span('x', fn () => throw new RuntimeException('boom')))
        ->toThrow(RuntimeException::class);
});

it('LogTracer registra lo span (con durata e attributi) e ritorna il valore', function () {
    $logger = recordingLogger();
    $tracer = new LogTracer($logger);

    $result = $tracer->span('pdp.check', fn (): int => 7, ['permission' => 'warehouse:stock.read']);

    expect($result)->toBe(7)
        ->and($logger->records)->toHaveCount(1)
        ->and($logger->records[0]['message'])->toBe('iam.span')
        ->and($logger->records[0]['context']['status'])->toBe('ok')
        ->and($logger->records[0]['context']['attr_permission'])->toBe('warehouse:stock.read')
        ->and($logger->records[0]['context'])->toHaveKey('duration_ms');
});

it('LogTracer registra l\'errore e RI-LANCIA (non altera il flusso di business)', function () {
    $logger = recordingLogger();
    $tracer = new LogTracer($logger);

    expect(fn () => $tracer->span('pdp.check', fn () => throw new RuntimeException('boom')))
        ->toThrow(RuntimeException::class);

    expect($logger->records)->toHaveCount(1)
        ->and($logger->records[0]['context']['status'])->toBe('error')
        ->and($logger->records[0]['context']['error_type'])->toBe(RuntimeException::class);
});
