<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Governance\Reviews\Reviewable;

use RuntimeException;

/**
 * L'item certifica un accesso la cui sorgente non è (più) registrata — tipicamente il modulo che
 * l'aveva creata è stato disinstallato.
 *
 * Non è un dettaglio da ingoiare: senza la sorgente l'accesso non è revocabile, e marcare l'item
 * `revoked` comunque scriverebbe nell'evidenza d'audit una revoca mai avvenuta. L'item resta
 * `pending` finché il modulo torna, o finché un umano decide diversamente.
 */
final class UnknownReviewableSource extends RuntimeException
{
    public function __construct(
        public readonly string $reviewableType,
        public readonly string $reviewItemId,
    ) {
        parent::__construct(
            "Nessuna ReviewableSource registrata per il tipo \"{$reviewableType}\": ".
            "l'item {$reviewItemId} non è revocabile."
        );
    }
}
