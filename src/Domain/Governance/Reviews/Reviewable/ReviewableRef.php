<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Governance\Reviews\Reviewable;

/**
 * Un accesso da certificare, così come lo produce una {@see ReviewableSource} all'apertura
 * della campagna. Porta già il reviewer e lo snapshot dei segnali: l'engine non ri-chiama la
 * sorgente per item (niente N+1 in apertura), e lo snapshot resta immutabile in `signals_json`.
 *
 * @phpstan-type Signals array<string, mixed>
 */
final readonly class ReviewableRef
{
    /**
     * @param  string  $type  tipo della sorgente (es. `grant`, `delegation_grant`)
     * @param  string  $id  identificatore stabile dell'accesso in quella sorgente
     * @param  string|null  $reviewer  chi deve certificare (`type:id`), null = solo admin
     * @param  Signals  $signals  segnali smart congelati all'apertura
     */
    public function __construct(
        public string $type,
        public string $id,
        public ?string $reviewer = null,
        public array $signals = [],
    ) {}
}
