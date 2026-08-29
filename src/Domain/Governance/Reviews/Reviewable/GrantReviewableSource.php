<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Governance\Reviews\Reviewable;

use Illuminate\Database\Eloquent\Builder;
use Padosoft\Iam\Domain\Audit\Pii\AuditRecorder;
use Padosoft\Iam\Domain\Authorization\Models\Grant;
use Padosoft\Iam\Domain\Governance\Reviews\Models\ReviewCampaign;
use Padosoft\Iam\Domain\Governance\Reviews\ReviewSignals;

/**
 * Sorgente built-in: i grant RBAC/ABAC (`iam_grants`). È il comportamento storico delle access
 * review, spostato dietro il contratto {@see ReviewableSource} così che il core non abbia più un
 * caso speciale e un modulo che ne aggiunge un'altra non sia un cittadino di seconda classe.
 *
 * Semantica invariata rispetto a prima del refactor: stessi filtri di scope, stesso isolamento
 * cross-tenant, stesso `event_type` d'audit (`iam.grant.revoked`).
 */
final class GrantReviewableSource implements ReviewableSource
{
    public const TYPE = 'grant';

    public function __construct(
        private readonly ReviewSignals $signals = new ReviewSignals,
        private readonly ?AuditRecorder $audit = null,
    ) {}

    public function type(): string
    {
        return self::TYPE;
    }

    public function label(): string
    {
        return 'Grants';
    }

    public function scoped(ReviewCampaign $campaign): iterable
    {
        foreach ($this->query($campaign)->cursor() as $grant) {
            yield new ReviewableRef(
                type: self::TYPE,
                id: $grant->id,
                reviewer: $this->resolveReviewer($campaign),
                signals: $this->signals->for($grant),
            );
        }
    }

    public function revoke(string $id, string $by, string $reason, array $context = []): bool
    {
        $grant = Grant::query()->find($id);
        if ($grant === null || $grant->revoked_at !== null) {
            return false; // già rimosso/revocato: niente da fare (idempotente)
        }

        $grant->revoke($by);

        ($this->audit ?? app(AuditRecorder::class))->record([
            'stream' => 'governance',
            'event_type' => 'iam.grant.revoked',
            'target_type' => 'grant',
            'target_id' => $grant->id,
            'organization_id' => $grant->organization_id,
            'metadata_json' => [
                'source' => 'access-review',
                'reason' => $reason,
                'revoked_by' => $by,
            ] + $context,
        ]);

        return true;
    }

    public function describeMany(array $ids): array
    {
        if ($ids === []) {
            return [];
        }

        $out = [];
        foreach (Grant::query()->whereIn('id', $ids)->get() as $grant) {
            $out[$grant->id] = [
                'subject_type' => $grant->subject_type,
                'subject_id' => $grant->subject_id,
                'privilege_type' => $grant->privilege_type,
                'privilege_key' => $grant->privilege_key,
                'application_key' => $grant->application_key,
                'effect' => $grant->effect,
            ];
        }

        return $out;
    }

    /**
     * Grant attivi che ricadono nello scope della campagna. Filtri additivi e fail-closed:
     * uno scope vuoto certifica TUTTI i grant attivi (full inventory).
     *
     * @return Builder<Grant>
     */
    private function query(ReviewCampaign $campaign): Builder
    {
        $scope = $campaign->scope_json ?? [];
        $query = Grant::query()->active();

        // Isolamento cross-tenant (fail-closed): una campagna di un'org certifica SOLO i grant di
        // quell'org. I grant globali (organization_id null) valgono per tutti i tenant → li può
        // certificare/revocare unicamente una campagna globale (organization_id null = full inventory),
        // mai una campagna di un singolo tenant, che altrimenti danneggerebbe gli altri.
        if ($campaign->organization_id !== null) {
            $query->where('organization_id', $campaign->organization_id);
        }

        $apps = self::stringList($scope['application_keys'] ?? null);
        if ($apps !== []) {
            $query->whereIn('application_key', $apps);
        }

        $types = self::stringList($scope['privilege_types'] ?? null);
        if ($types !== []) {
            $query->whereIn('privilege_type', $types);
        }

        $subjects = self::stringList($scope['subject_types'] ?? null);
        if ($subjects !== []) {
            $query->whereIn('subject_type', $subjects);
        }

        if (($scope['only_privileged'] ?? false) === true) {
            $query->where('is_privileged', true);
        }

        return $query;
    }

    private function resolveReviewer(ReviewCampaign $campaign): ?string
    {
        // v1: strategia 'named' → reviewer esplicito nello scope. 'manager'/'resource_owner'
        // richiedono la directory sync / l'app-owner registry (v2): per ora restano null
        // (l'item è comunque visibile a un admin con iam:access_review.manage).
        if ($campaign->reviewer_strategy === 'named') {
            $named = $campaign->scope_json['reviewer'] ?? null;

            return is_string($named) && $named !== '' ? $named : null;
        }

        return null;
    }

    /**
     * @return list<string>
     */
    public static function stringList(mixed $value): array
    {
        if (!is_array($value)) {
            return [];
        }

        $out = [];
        foreach ($value as $v) {
            if (is_string($v) && $v !== '') {
                $out[] = $v;
            }
        }

        return $out;
    }
}
