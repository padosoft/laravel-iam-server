<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Http;
use Padosoft\Iam\Observability\LogTracer;
use Padosoft\Iam\Observability\NullTracer;
use Padosoft\Iam\Observability\OtlpTracer;
use Padosoft\Iam\Observability\StackTracer;
use Padosoft\Iam\Observability\Tracer;
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

it('OtlpTracer buffers spans and flushes one OTLP/HTTP JSON batch to /v1/traces', function () {
    Http::fake(['*' => Http::response('', 200)]);
    $tracer = new OtlpTracer('http://collector:4318', 'laravel-iam', 5);

    expect($tracer->span('pdp.check', fn (): int => 7, ['permission' => 'warehouse:stock.read']))->toBe(7);
    Http::assertNothingSent(); // buffered, not sent per span (no hot-path round-trip)

    $tracer->flush();

    Http::assertSent(function ($request) {
        $body = $request->data();

        return str_ends_with($request->url(), '/v1/traces')
            && $body['resourceSpans'][0]['resource']['attributes'][0]['value']['stringValue'] === 'laravel-iam'
            && $body['resourceSpans'][0]['scopeSpans'][0]['spans'][0]['name'] === 'pdp.check'
            && strlen($body['resourceSpans'][0]['scopeSpans'][0]['spans'][0]['traceId']) === 32;
    });
});

it('OtlpTracer re-throws the callback exception (records it, never swallows)', function () {
    Http::fake(['*' => Http::response('', 200)]);
    $tracer = new OtlpTracer('http://collector:4318', 'svc');

    expect(fn () => $tracer->span('x', fn () => throw new RuntimeException('boom')))->toThrow(RuntimeException::class);
});

it('OtlpTracer flush is best-effort — a down collector never throws', function () {
    Http::fake(['*' => Http::response('kaboom', 500)]);
    $tracer = new OtlpTracer('http://collector:4318', 'svc');
    $tracer->event('probe');

    $tracer->flush(); // must not throw despite the 500
    expect(true)->toBeTrue();
});

it('StackTracer fans out to log AND otlp', function () {
    Http::fake(['*' => Http::response('', 200)]);
    $logger = recordingLogger();
    $otlp = new OtlpTracer('http://collector:4318', 'svc');
    $stack = new StackTracer(new LogTracer($logger), $otlp);

    expect($stack->span('pdp.check', fn (): int => 1))->toBe(1);
    $stack->flush();

    expect($logger->records)->toHaveCount(1);            // logged locally
    Http::assertSent(fn ($r) => str_ends_with($r->url(), '/v1/traces')); // AND exported
});

it('resolves IAM_TRACER to the right tracer, fail-safe on a missing OTLP endpoint', function () {
    config(['iam.observability.tracer' => 'otlp', 'iam.observability.otel_endpoint' => 'http://collector:4318']);
    app()->forgetInstance(Tracer::class);
    expect(app(Tracer::class))->toBeInstanceOf(OtlpTracer::class);

    config(['iam.observability.tracer' => 'stack']);
    app()->forgetInstance(Tracer::class);
    expect(app(Tracer::class))->toBeInstanceOf(StackTracer::class);

    // otlp selected but no endpoint → NullTracer, never a misconfigured export.
    config(['iam.observability.tracer' => 'otlp', 'iam.observability.otel_endpoint' => null]);
    app()->forgetInstance(Tracer::class);
    expect(app(Tracer::class))->toBeInstanceOf(NullTracer::class);
});
