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
     */
    public function __construct(
        public SubjectRef $actor,
        public ?string $organizationId = null,
        public array $scopes = [],
    ) {}

    public function actorRef(): string
    {
        return (string) $this->actor;
    }
}
