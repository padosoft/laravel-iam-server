<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Authorization\Relations;

use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Iam\Domain\Audit\Pii\AuditRecorder;
use Padosoft\Iam\Domain\Authorization\Models\Relation;
use Padosoft\Iam\Domain\Authorization\Pdp\ResourceRef;
use Padosoft\Iam\Domain\Organizations\Models\Organization;

/**
 * Unico punto di scrittura delle tuple ReBAC (doc 18 §5): idempotente (dedup per identity_hash),
 * imposta consistency_token = policy_version dell'org al write, ed emette audit su ogni mutazione.
 * Mai insert diretti sul model: così dedup + audit + token restano garantiti.
 */
final class RelationWriter
{
    public function __construct(private readonly ?AuditRecorder $audit = null) {}

    /**
     * Crea (o riattiva) la tupla `(subject, relation, object)`. Idempotente: la stessa identità non
     * crea duplicati. Emette `iam.relation.granted`.
     *
     * @param  array<string, mixed>|null  $condition
     */
    public function grant(SubjectRef $subject, string $relation, ResourceRef $object, ?array $condition = null, ?string $organizationId = null, ?string $createdBy = null): Relation
    {
        $hash = $this->identityHash($organizationId, $subject, $relation, $object);

        $tuple = Relation::query()->where('identity_hash', $hash)->first();
        if ($tuple === null) {
            $tuple = new Relation;
        }
        $tuple->fill([
            'organization_id' => $organizationId,
            'subject_type' => $subject->type,
            'subject_id' => $subject->id,
            'relation' => $relation,
            'object_type' => $object->type,
            'object_id' => $object->id,
            'condition' => $condition,
            'created_by' => $createdBy,
        ]);
        // Riattiva un'eventuale tupla revocata con la stessa identità (forceFill: revoked_at non è fillable).
        $tuple->forceFill([
            'revoked_at' => null,
            'consistency_token' => $this->policyVersion($organizationId),
        ])->save();

        $this->emit('iam.relation.granted', $tuple);

        return $tuple;
    }

    /**
     * Revoca la tupla `(subject, relation, object)` se esiste e attiva. Idempotente. Emette
     * `iam.relation.revoked`. Ritorna true se qualcosa è stato revocato.
     */
    public function revoke(SubjectRef $subject, string $relation, ResourceRef $object, ?string $organizationId = null): bool
    {
        $hash = $this->identityHash($organizationId, $subject, $relation, $object);
        $tuple = Relation::query()->where('identity_hash', $hash)->whereNull('revoked_at')->first();
        if ($tuple === null) {
            return false;
        }
        $tuple->revoke();
        $this->emit('iam.relation.revoked', $tuple);

        return true;
    }

    private function identityHash(?string $organizationId, SubjectRef $subject, string $relation, ResourceRef $object): string
    {
        return hash('sha256', json_encode([
            $organizationId,
            $subject->type,
            $subject->id,
            $relation,
            $object->type,
            $object->id,
        ], JSON_THROW_ON_ERROR));
    }

    private function policyVersion(?string $organizationId): int
    {
        if ($organizationId === null) {
            return 0;
        }
        $value = Organization::query()->whereKey($organizationId)->value('policy_version');

        return is_numeric($value) ? (int) $value : 0;
    }

    private function emit(string $eventType, Relation $tuple): void
    {
        ($this->audit ?? app(AuditRecorder::class))->record([
            'stream' => 'authorization',
            'event_type' => $eventType,
            'target_type' => 'relation',
            'target_id' => $tuple->id,
            'organization_id' => $tuple->organization_id,
            'metadata_json' => [
                'subject' => $tuple->subject_type.':'.$tuple->subject_id,
                'relation' => $tuple->relation,
                'object' => $tuple->object_type.':'.$tuple->object_id,
            ],
        ]);
    }
}
