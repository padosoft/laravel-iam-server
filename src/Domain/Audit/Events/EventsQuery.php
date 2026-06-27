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
    public function page(string $stream, int $limit = 50, ?string $cursor = null, ?string $typePrefix = null): EventsPage
    {
        $limit = max(1, min($limit, 500));

        $builder = AuditEvent::query()
            ->where('stream', $stream)
            ->orderBy('seq');

        if ($cursor !== null && ctype_digit($cursor)) {
            $builder->where('seq', '>', (int) $cursor);
        }

        if ($typePrefix !== null && $typePrefix !== '') {
            // Escape dei metacaratteri LIKE + clausola ESCAPE esplicita: SQLite non ha un escape
            // char di default per LIKE, quindi senza ESCAPE un prefisso con %/_ filtrerebbe male.
            $escaped = str_replace(['\\', '%', '_'], ['\\\\', '\\%', '\\_'], $typePrefix);
            $builder->whereRaw("event_type LIKE ? ESCAPE '\\'", [$escaped.'%']);
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
