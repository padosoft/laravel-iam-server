<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Audit\Events;

use Padosoft\Iam\Domain\Audit\Models\AuditEvent;

/**
 * Pagina di eventi di audit con cursore stabile (doc 12 §5). `nextCursor` è null quando non ci
 * sono altri eventi.
 */
final class EventsPage
{
    /**
     * @param  list<AuditEvent>  $events
     */
    public function __construct(
        public readonly array $events,
        public readonly ?string $nextCursor,
    ) {}
}
