<?php

declare(strict_types=1);

namespace Padosoft\Iam\Http\Admin\Support;

use Padosoft\Iam\Contracts\Support\SubjectRef;

/**
 * Identità risolta del chiamante dell'Admin API (doc 16 §6). È l'attore di OGNI decisione di
 * autorizzazione e di OGNI audit event delle mutazioni admin. Immutabile: viene popolata una volta
 * dal middleware di autenticazione e poi solo letta.
 */
final readonly class AdminContext
{
    /**
     * @param  list<string>  $scopes
     * @param  string  $aal  livello di assurance dell'attore (aal1|aal2|aal3), derivato dal token.
     *                       Default `aal1` = fail-closed: senza una prova di step-up nel token l'attore
     *                       vale il livello più basso e non supera i permessi `requires_step_up`.
     */
    public function __construct(
        public SubjectRef $actor,
        public ?string $organizationId = null,
        public array $scopes = [],
        public string $aal = 'aal1',
    ) {}

    public function actorRef(): string
    {
        return (string) $this->actor;
    }
}
