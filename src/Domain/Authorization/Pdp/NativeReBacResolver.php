<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Authorization\Pdp;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Collection;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Iam\Domain\Authorization\Models\Relation;

/**
 * Motore ReBAC nativo su SQL per i casi comuni (doc 18 §6): relazioni dirette, nesting gruppi,
 * gerarchia risorse, implicazione fra relazioni. Bounded (MAX_DEPTH + cycle-guard) e fail-closed:
 * profondità superata, ciclo, risorsa assente, token insufficiente ⇒ la relazione NON vale.
 *
 * Traversata iterativa (BFS) su query indicizzate (forward/reverse) — portabile su SQLite/MySQL/PG,
 * niente recursive CTE specifico per dialetto. Gli insiemi espansi sono bounded, l'EXISTS finale è
 * una sola query.
 */
final class NativeReBacResolver
{
    /**
     * Salti massimi PER ASSE nell'espansione (hard cap fail-closed): fino a MAX_DEPTH livelli di
     * nesting gruppi E fino a MAX_DEPTH livelli di gerarchia risorse, valutati indipendentemente.
     */
    public const MAX_DEPTH = 10;

    public function __construct(
        private readonly RelationRewrite $rewrite = new RelationRewrite,
        private readonly ConditionEvaluator $conditions = new ConditionEvaluator,
    ) {}

    /**
     * Il soggetto ha (direttamente, via gruppi, via gerarchia o per implicazione) `$relation` su `$object`?
     *
     * @param  array<string, mixed>  $context  valutazione delle condition sulle tuple
     */
    public function hasRelation(SubjectRef $subject, string $relation, ResourceRef $object, array $context = [], ?string $organizationId = null, int $minToken = 0): RelationResult
    {
        $rels = $this->rewrite->satisfying($relation);
        $subjects = $this->expandGroups($subject, $organizationId); // [key => chain]
        $targets = $this->expandHierarchy($object, $organizationId); // [key => chain]

        /** @var Collection<int, Relation> $candidates */
        $candidates = Relation::query()->active()
            ->whereIn('relation', $rels)
            ->where('consistency_token', '>=', $minToken)
            ->where(fn (Builder $w) => $w->whereNull('organization_id')->orWhere('organization_id', $organizationId))
            ->where(fn (Builder $w) => $this->matchAnyRef($w, 'subject_type', 'subject_id', array_keys($subjects)))
            ->where(fn (Builder $w) => $this->matchAnyRef($w, 'object_type', 'object_id', array_keys($targets)))
            ->get();

        foreach ($candidates as $tuple) {
            // Condition ABAC sulla tupla (fail-closed: condizione non soddisfatta ⇒ tupla ignorata).
            if ($this->conditions->failed($tuple->condition ?? [], $context) !== []) {
                continue;
            }
            $subjKey = $tuple->subject_type.':'.$tuple->subject_id;
            $objKey = $tuple->object_type.':'.$tuple->object_id;
            $edge = "{$subjKey} —{$tuple->relation}→ {$objKey}";

            return new RelationResult(true, [
                ...($subjects[$subjKey] ?? []),
                $edge,
                ...($targets[$objKey] ?? []),
            ]);
        }

        return RelationResult::deny();
    }

    /**
     * Chi ha `$relation` su `$object` (list-subjects, doc 18 §6.2). Reverse-index forward + espansione
     * gruppi verso i membri + gerarchia verso gli antenati. Deduplicato e bounded (LIMIT).
     *
     * @return list<SubjectRef>
     */
    public function listSubjects(string $relation, ResourceRef $object, ?string $organizationId = null, int $limit = 100): array
    {
        $rels = $this->rewrite->satisfying($relation);
        $targets = $this->expandHierarchy($object, $organizationId);

        /** @var Collection<int, Relation> $tuples */
        $tuples = Relation::query()->active()
            ->whereIn('relation', $rels)
            ->where(fn (Builder $w) => $w->whereNull('organization_id')->orWhere('organization_id', $organizationId))
            ->where(fn (Builder $w) => $this->matchAnyRef($w, 'object_type', 'object_id', array_keys($targets)))
            ->get();

        // Per ogni soggetto con la relazione, espandi verso i membri (se è un gruppo).
        $out = [];
        foreach ($tuples as $tuple) {
            $ref = new SubjectRef($tuple->subject_type, $tuple->subject_id);
            foreach ($this->expandMembers($ref, $organizationId) as $member) {
                $out[$member->type.':'.$member->id] = $member;
            }
        }

        return array_slice(array_values($out), 0, $limit);
    }

    /**
     * Su cosa `$subject` ha `$relation` (list-resources, doc 18 §6.3). Reverse-index + discesa gerarchia.
     *
     * @return list<array{type: string, id: string}>
     */
    public function listResources(SubjectRef $subject, string $relation, ?string $organizationId = null, int $limit = 100): array
    {
        $rels = $this->rewrite->satisfying($relation);
        $subjects = $this->expandGroups($subject, $organizationId);

        /** @var Collection<int, Relation> $tuples */
        $tuples = Relation::query()->active()
            ->whereIn('relation', $rels)
            ->where(fn (Builder $w) => $w->whereNull('organization_id')->orWhere('organization_id', $organizationId))
            ->where(fn (Builder $w) => $this->matchAnyRef($w, 'subject_type', 'subject_id', array_keys($subjects)))
            ->get();

        $out = [];
        foreach ($tuples as $tuple) {
            $obj = new ResourceRef($tuple->object_type, $tuple->object_id);
            foreach ($this->expandDescendants($obj, $organizationId) as $descendant) {
                $out[$descendant->type.':'.$descendant->id] = ['type' => $descendant->type, 'id' => $descendant->id];
            }
        }

        return array_slice(array_values($out), 0, $limit);
    }

    /**
     * {S} ∪ gruppi di cui S è membro (transitivo, bounded). Chiave "type:id" → cammino dal soggetto.
     *
     * @return array<string, list<string>>
     */
    private function expandGroups(SubjectRef $subject, ?string $organizationId): array
    {
        $start = $subject->type.':'.$subject->id;
        $result = [$start => []];
        $frontier = [$start => new SubjectRef($subject->type, $subject->id)];

        for ($depth = 0; $depth < self::MAX_DEPTH && $frontier !== []; $depth++) {
            /** @var Collection<int, Relation> $edges */
            $edges = Relation::query()->active()
                ->where('relation', 'member')
                ->where(fn (Builder $w) => $w->whereNull('organization_id')->orWhere('organization_id', $organizationId))
                ->where(fn (Builder $w) => $this->matchAnyRef($w, 'subject_type', 'subject_id', array_keys($frontier)))
                ->get();

            $next = [];
            foreach ($edges as $edge) {
                $from = $edge->subject_type.':'.$edge->subject_id;
                $to = $edge->object_type.':'.$edge->object_id;
                if (isset($result[$to])) {
                    continue; // cycle-guard / già visto
                }
                $result[$to] = [...($result[$from] ?? []), "{$from} —member→ {$to}"];
                $next[$to] = new SubjectRef($edge->object_type, $edge->object_id);
            }
            $frontier = $next;
        }

        return $result;
    }

    /**
     * {O} ∪ antenati via `parent` (transitivo, bounded). Chiave "type:id" → cammino verso l'antenato.
     *
     * @return array<string, list<string>>
     */
    private function expandHierarchy(ResourceRef $object, ?string $organizationId): array
    {
        $start = $object->type.':'.$object->id;
        $result = [$start => []];
        $frontier = [$start => new ResourceRef($object->type, $object->id)];

        for ($depth = 0; $depth < self::MAX_DEPTH && $frontier !== []; $depth++) {
            /** @var Collection<int, Relation> $edges */
            $edges = Relation::query()->active()
                ->where('relation', 'parent')
                ->where(fn (Builder $w) => $w->whereNull('organization_id')->orWhere('organization_id', $organizationId))
                ->where(fn (Builder $w) => $this->matchAnyRef($w, 'subject_type', 'subject_id', array_keys($frontier)))
                ->get();

            $next = [];
            foreach ($edges as $edge) {
                $from = $edge->subject_type.':'.$edge->subject_id;
                $to = $edge->object_type.':'.$edge->object_id;
                if (isset($result[$to])) {
                    continue;
                }
                $result[$to] = [...($result[$from] ?? []), "{$from} —parent→ {$to}"];
                $next[$to] = new ResourceRef($edge->object_type, $edge->object_id);
            }
            $frontier = $next;
        }

        return $result;
    }

    /**
     * {G} ∪ membri (transitivo, bounded), verso il basso. Usato da list-subjects.
     *
     * @return list<SubjectRef>
     */
    private function expandMembers(SubjectRef $group, ?string $organizationId): array
    {
        $startKey = $group->type.':'.$group->id;
        $seen = [$startKey => $group];
        $frontier = [$startKey => $group];

        for ($depth = 0; $depth < self::MAX_DEPTH && $frontier !== []; $depth++) {
            /** @var Collection<int, Relation> $edges */
            $edges = Relation::query()->active()
                ->where('relation', 'member')
                ->where(fn (Builder $w) => $w->whereNull('organization_id')->orWhere('organization_id', $organizationId))
                ->where(fn (Builder $w) => $this->matchAnyRef($w, 'object_type', 'object_id', array_keys($frontier)))
                ->get();

            $next = [];
            foreach ($edges as $edge) {
                $key = $edge->subject_type.':'.$edge->subject_id;
                if (isset($seen[$key])) {
                    continue;
                }
                $ref = new SubjectRef($edge->subject_type, $edge->subject_id);
                $seen[$key] = $ref;
                $next[$key] = $ref;
            }
            $frontier = $next;
        }

        return array_values($seen);
    }

    /**
     * {O} ∪ discendenti via `parent` (transitivo, bounded), verso il basso. Usato da list-resources.
     *
     * @return list<ResourceRef>
     */
    private function expandDescendants(ResourceRef $object, ?string $organizationId): array
    {
        $startKey = $object->type.':'.$object->id;
        $seen = [$startKey => $object];
        $frontier = [$startKey => $object];

        for ($depth = 0; $depth < self::MAX_DEPTH && $frontier !== []; $depth++) {
            /** @var Collection<int, Relation> $edges */
            $edges = Relation::query()->active()
                ->where('relation', 'parent')
                ->where(fn (Builder $w) => $w->whereNull('organization_id')->orWhere('organization_id', $organizationId))
                ->where(fn (Builder $w) => $this->matchAnyRef($w, 'object_type', 'object_id', array_keys($frontier)))
                ->get();

            $next = [];
            foreach ($edges as $edge) {
                $key = $edge->subject_type.':'.$edge->subject_id;
                if (isset($seen[$key])) {
                    continue;
                }
                $ref = new ResourceRef($edge->subject_type, $edge->subject_id);
                $seen[$key] = $ref;
                $next[$key] = $ref;
            }
            $frontier = $next;
        }

        return array_values($seen);
    }

    /**
     * Aggiunge al builder un OR di coppie composite (type,id) dato un insieme di chiavi "type:id".
     * Fail-closed: insieme vuoto ⇒ `whereRaw('1 = 0')` (nessun match), mai un match aperto.
     *
     * @param  Builder<Relation>  $w
     * @param  list<string>  $keys
     */
    private function matchAnyRef(Builder $w, string $typeCol, string $idCol, array $keys): void
    {
        if ($keys === []) {
            $w->whereRaw('1 = 0');

            return;
        }
        foreach ($keys as $key) {
            $pos = strpos($key, ':');
            $type = $pos === false ? $key : substr($key, 0, $pos);
            $id = $pos === false ? '' : substr($key, $pos + 1);
            $w->orWhere(fn (Builder $q) => $q->where($typeCol, $type)->where($idCol, $id));
        }
    }
}
