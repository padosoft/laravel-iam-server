<?php

declare(strict_types=1);

namespace Padosoft\Iam\Http\Admin;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Padosoft\Iam\Domain\Audit\Pii\AuditRecorder;
use Padosoft\Iam\Http\Admin\Support\AdminContext;
use Padosoft\Iam\Http\Admin\Support\ApiProblemException;

/**
 * Base dei controller dell'Admin API. Centralizza: accesso all'attore autenticato, paginazione
 * cursor-based (doc 16 §6), risposte JSON coerenti e audit di OGNI mutazione (doc 12) con l'attore
 * risolto. I controller concreti restano sottili e dichiarativi.
 */
abstract class AdminController
{
    /** Attore autenticato (garantito dal middleware AdminAuthenticate). */
    protected function context(Request $request): AdminContext
    {
        $context = $request->attributes->get('iam_admin_context');
        if (!$context instanceof AdminContext) {
            throw ApiProblemException::unauthorized();
        }

        return $context;
    }

    /**
     * @param  array<string, mixed>  $data
     */
    protected function ok(array $data, int $status = 200): JsonResponse
    {
        return new JsonResponse(['data' => $data], $status);
    }

    /**
     * Paginazione cursor-based su una chiave ordinabile (ULID `id` di default). Il cursore è l'ultimo
     * id della pagina; deterministica e stabile sotto inserimenti concorrenti (no offset-drift).
     *
     * @param  Builder<covariant Model>  $query
     * @param  callable(Model): array<string, mixed>  $map
     * @param  (callable(Collection<int, Model>): void)|null  $prepare  gira una
     *                                                                  volta sulla pagina materializzata, prima del map: per risolvere in blocco dati che non
     *                                                                  stanno nella riga senza pagare una query per riga.
     */
    protected function paginate(Builder $query, Request $request, callable $map, string $key = 'id', ?callable $prepare = null): JsonResponse
    {
        $limit = $this->limit($request);
        $cursor = $request->query('cursor');
        if (is_string($cursor) && $cursor !== '') {
            $query->where($key, '>', $cursor);
        }

        // Order/limit mutano $query in-place: chiamiamo get() sulla variabile tipata Builder<TModel>
        // (non sul return concatenato) così PHPStan conserva il binding generico → Collection<TModel>.
        $query->orderBy($key)->limit($limit + 1);
        $rows = $query->get();
        $hasMore = $rows->count() > $limit;

        // Hook opzionale: gira UNA volta sulla pagina già materializzata, prima del map. Serve a chi
        // deve risolvere in blocco dati che non stanno nella riga (es. i campi di riepilogo di un
        // item polimorfico, che vivono in un'altra sorgente) senza pagare una query per riga.
        if ($prepare !== null) {
            $prepare($rows);
        }

        $data = [];
        $lastKey = null;
        $i = 0;
        foreach ($rows as $row) {
            if ($i >= $limit) {
                break;
            }
            $data[] = $map($row);
            $lastKey = $row->getAttribute($key);
            $i++;
        }

        $nextCursor = $hasMore && is_scalar($lastKey) ? (string) $lastKey : null;

        return new JsonResponse([
            'data' => $data,
            'next_cursor' => $nextCursor,
        ]);
    }

    /**
     * Esegue un'azione di dominio mappandone le eccezioni su problem+json: errori d'input
     * (InvalidArgumentException) → 422, violazioni di stato/conflitti (RuntimeException) → 409.
     * Così le eccezioni del dominio non emergono mai come 500 opachi.
     *
     * @template T
     *
     * @param  callable(): T  $action
     * @return T
     */
    protected function runDomain(callable $action): mixed
    {
        try {
            return $action();
        } catch (ApiProblemException $e) {
            throw $e; // già un problem+json (es. 404 da una find interna): non ri-mappare.
        } catch (\InvalidArgumentException $e) {
            throw ApiProblemException::unprocessable($e->getMessage());
        } catch (\RuntimeException $e) {
            throw ApiProblemException::conflict($e->getMessage());
        }
    }

    private function limit(Request $request): int
    {
        $raw = $request->query('limit');
        $limit = is_numeric($raw) ? (int) $raw : 25;

        return max(1, min(100, $limit));
    }

    /**
     * Audit di una mutazione admin (doc 16 §6: ogni mutazione → audit con before/after e attore).
     *
     * @param  array<string, mixed>  $extra
     * @param  array<string, mixed>|null  $before
     * @param  array<string, mixed>|null  $after
     */
    protected function audit(Request $request, string $eventType, string $targetType, ?string $targetId, array $extra = [], ?array $before = null, ?array $after = null): void
    {
        $context = $this->context($request);
        $correlation = $request->headers->get('Correlation-Id');

        // Thread the request IP/UA so the AuditRecorder can honour iam.audit.ip_mode/ua_mode (hash by
        // default; `full` records them in clear for forensics). Without this the audit ip/ua stay null.
        app(AuditRecorder::class)->record([
            'stream' => 'admin',
            'event_type' => $eventType,
            'target_type' => $targetType,
            'target_id' => $targetId,
            'organization_id' => $context->organizationId,
            'correlation_id' => is_string($correlation) ? $correlation : null,
            'before_json' => $before,
            'after_json' => $after,
            'metadata_json' => array_merge(['actor' => $context->actorRef()], $extra),
        ], [], null, $request->ip(), $request->userAgent());
    }
}
