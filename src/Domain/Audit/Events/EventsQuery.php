<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Audit\Events;

use Padosoft\Iam\Domain\Audit\Models\AuditEvent;

/**
 * Lettura paginata degli eventi di audit sigillati (doc 12 §5). Cursor pagination stabile: il
 * cursore è il `seq` (univoco per stream, monotono) → nessun evento perso/duplicato anche sotto
 * scrittura concorrente, a differenza dell'offset. Filtro opzionale per prefisso di tipo (grant.*).
 */
final class EventsQuery
{
    public function page(string $stream, int $limit = 50, ?string $cursor = null, ?string $typePrefix = null, ?string $organizationId = null): EventsPage
    {
        $limit = max(1, min($limit, 500));

        $builder = AuditEvent::query()
            ->where('stream', $stream)
            ->orderBy('seq');

        // IAM-03: tenant isolation on shared streams. Streams like 'admin'/'governance'/'authorization'
        // commingle every tenant's events (the tenant lives in the organization_id column). A tenant-bound
        // caller must only ever read their own org's rows, so scope by organization_id when an org is given.
        // A null org (global admin) reads across tenants; that path is gated by the audit.read permission.
        if ($organizationId !== null) {
            $builder->where('organization_id', $organizationId);
        }

        if ($cursor !== null && ctype_digit($cursor)) {
            $builder->where('seq', '>', (int) $cursor);
        }

        if ($typePrefix !== null && $typePrefix !== '') {
            // Escape the LIKE metacharacters (%, _) and the escape char itself. The escape char is '!',
            // NOT backslash: on MySQL a backslash inside a string literal is itself an escape, so
            // ESCAPE '\' is a syntax error (it works on SQLite but 500s on MySQL). '!' is literal on both.
            $escaped = str_replace(['!', '%', '_'], ['!!', '!%', '!_'], $typePrefix);
            $builder->whereRaw("event_type LIKE ? ESCAPE '!'", [$escaped.'%']);
        }

        // Prendiamo un elemento in più per sapere se esiste una pagina successiva.
        /** @var list<AuditEvent> $rows */
        $rows = $builder->limit($limit + 1)->get()->all();

        $hasMore = count($rows) > $limit;
        $events = $hasMore ? array_slice($rows, 0, $limit) : $rows;
        $nextCursor = $hasMore && $events !== [] ? (string) $events[count($events) - 1]->seq : null;

        return new EventsPage($events, $nextCursor);
    }
}
