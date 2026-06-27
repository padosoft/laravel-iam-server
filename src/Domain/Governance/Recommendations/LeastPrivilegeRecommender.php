<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Governance\Recommendations;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Carbon;
use Illuminate\Support\Collection;
use Padosoft\Iam\Domain\Authorization\Models\Grant;
use Padosoft\Iam\Domain\Authorization\Models\Role;

/**
 * Recommender deterministico di least-privilege + anomaly (doc 14 §7). Scansiona grant e ruoli e
 * produce raccomandazioni DRAFT (proposte, mai azioni automatiche). Due classi di regole:
 *  A) immediate (nessuno storico): permesso diretto, ruolo troppo ampio, combinazione tossica;
 *  B) temporali (cattura dati v1): grant non usato oltre soglia, grant permanente privilegiato.
 * La spiegazione AI è polish di v2 (doc 15): qui solo regole riproducibili.
 */
final class LeastPrivilegeRecommender
{
    /**
     * @return list<Recommendation>
     */
    public function analyze(?string $organizationId = null): array
    {
        $grants = $this->grants($organizationId)->get();

        return [
            ...$this->directPermissions($grants),
            ...$this->unusedGrants($grants),
            ...$this->permanentPrivileged($grants),
            ...$this->wideRoles($organizationId, $grants),
            ...$this->toxicCombinations($grants),
        ];
    }

    /**
     * Regola A: grant `permission` diretto → candidato a diventare ruolo (governance per ruoli).
     *
     * @param  Collection<int, Grant>  $grants
     * @return list<Recommendation>
     */
    private function directPermissions(Collection $grants): array
    {
        $out = [];
        foreach ($grants as $g) {
            if ($g->privilege_type === 'permission') {
                $out[] = new Recommendation(
                    type: 'direct_permission',
                    severity: 'low',
                    recommendation: 'convert_to_role',
                    targetRef: $g->id,
                    subject: $g->subject_type.':'.$g->subject_id,
                    detail: "Permesso diretto {$g->privilege_key}: valuta l'assegnazione via ruolo.",
                    evidence: ['privilege_key' => $g->privilege_key],
                );
            }
        }

        return $out;
    }

    /**
     * Regola B: grant non usato da oltre `unused_days` (o mai usato, oltre il periodo di grazia).
     *
     * @param  Collection<int, Grant>  $grants
     * @return list<Recommendation>
     */
    private function unusedGrants(Collection $grants): array
    {
        $threshold = $this->threshold('unused_days', 90);
        $out = [];
        foreach ($grants as $g) {
            $unusedDays = $this->unusedDays($g, $threshold);
            if ($unusedDays === null) {
                continue;
            }
            $out[] = new Recommendation(
                type: 'unused_grant',
                severity: $g->is_privileged ? 'high' : 'medium',
                recommendation: 'revoke',
                targetRef: $g->id,
                subject: $g->subject_type.':'.$g->subject_id,
                detail: "Accesso {$g->privilege_key} non usato da {$unusedDays} giorni (soglia {$threshold}): candidato a revoca.",
                evidence: ['last_used_at' => $g->last_used_at?->toIso8601String(), 'unused_days' => $unusedDays],
            );
        }

        return $out;
    }

    /**
     * Regola B: grant permanente (valid_until null) e privilegiato → candidato a temporaneo (PIM).
     *
     * @param  Collection<int, Grant>  $grants
     * @return list<Recommendation>
     */
    private function permanentPrivileged(Collection $grants): array
    {
        $out = [];
        foreach ($grants as $g) {
            if ($g->is_privileged && $g->valid_until === null) {
                $out[] = new Recommendation(
                    type: 'permanent_privileged',
                    severity: 'high',
                    recommendation: 'make_temporary',
                    targetRef: $g->id,
                    subject: $g->subject_type.':'.$g->subject_id,
                    detail: "Grant privilegiato permanente {$g->privilege_key}: candidato a finestra temporanea (PIM/JIT).",
                    evidence: ['is_privileged' => true, 'valid_until' => null],
                );
            }
        }

        return $out;
    }

    /**
     * Regola A: ruolo con più permessi della soglia → candidato a split. I ruoli sono catalogo per-app
     * (manifest), non per-tenant; quando si scansiona una org specifica restringiamo ai ruoli davvero
     * concessi in quello scope, per non rovesciare nel report ruoli irrilevanti per il tenant.
     *
     * @param  Collection<int, Grant>  $grants  grant già filtrati per org
     * @return list<Recommendation>
     */
    private function wideRoles(?string $organizationId, Collection $grants): array
    {
        $threshold = $this->threshold('wide_role_permissions', 50);
        $query = Role::query()->whereNull('deprecated_at')->withCount('permissions');

        if ($organizationId !== null) {
            $scopedRoleKeys = $grants
                ->where('privilege_type', 'role')
                ->pluck('privilege_key')
                ->unique()
                ->all();
            if ($scopedRoleKeys === []) {
                return [];
            }
            $query->whereIn('full_key', $scopedRoleKeys);
        }

        $out = [];
        foreach ($query->get() as $role) {
            $rawCount = $role->getAttribute('permissions_count');
            $count = is_numeric($rawCount) ? (int) $rawCount : 0;
            if ($count > $threshold) {
                $out[] = new Recommendation(
                    type: 'wide_role',
                    severity: 'medium',
                    recommendation: 'split_role',
                    targetRef: $role->full_key,
                    subject: null,
                    detail: "Ruolo {$role->full_key} con {$count} permessi (soglia {$threshold}): candidato a split.",
                    evidence: ['permissions_count' => $count],
                );
            }
        }

        return $out;
    }

    /**
     * Regola A (anomaly/SoD §6): un soggetto i cui grant attivi coprono TUTTE le chiavi di una
     * combinazione tossica configurata → finding "Rischio SoD". Config:
     *   'toxic_combinations' => [ ['name' => '...', 'all_of' => ['app:perm.a', 'app:perm.b']], ... ]
     *
     * @param  Collection<int, Grant>  $grants
     * @return list<Recommendation>
     */
    private function toxicCombinations(Collection $grants): array
    {
        $combos = config('iam-governance.toxic_combinations', []);
        if (!is_array($combos) || $combos === []) {
            return [];
        }

        // Indicizza le chiavi (permission/role) possedute per soggetto.
        $bySubject = [];
        foreach ($grants as $g) {
            if ($g->effect !== 'permit') {
                continue;
            }
            $bySubject[$g->subject_type.':'.$g->subject_id][$g->privilege_key] = true;
        }

        $out = [];
        foreach ($bySubject as $subject => $held) {
            foreach ($combos as $combo) {
                if (!is_array($combo)) {
                    continue;
                }
                $allOf = array_values(array_filter($this->arr($combo['all_of'] ?? null), 'is_string'));
                if ($allOf === []) {
                    continue;
                }
                $covered = array_filter($allOf, static fn (string $k): bool => isset($held[$k]));
                if (count($covered) === count($allOf)) {
                    $name = is_string($combo['name'] ?? null) ? $combo['name'] : 'toxic';
                    $out[] = new Recommendation(
                        type: 'toxic_combination',
                        severity: 'high',
                        recommendation: 'review_sod',
                        targetRef: $subject,
                        subject: $subject,
                        detail: "Combinazione tossica \"{$name}\": il soggetto detiene ".implode(' + ', $allOf).'.',
                        evidence: ['combination' => $name, 'all_of' => $allOf],
                    );
                }
            }
        }

        return $out;
    }

    /** Giorni di non-uso se oltre soglia, altrimenti null. Un grant appena creato non è "non usato". */
    private function unusedDays(Grant $g, int $threshold): ?int
    {
        if ($g->last_used_at !== null) {
            $days = (int) $g->last_used_at->diffInDays(now());

            return $days >= $threshold ? $days : null;
        }

        // Mai usato: conta dalla creazione, con periodo di grazia = soglia (no falsi positivi su grant nuovi).
        $createdAt = $g->getAttribute('created_at');
        if (!$createdAt instanceof \DateTimeInterface) {
            return null;
        }
        $days = (int) Carbon::instance($createdAt)->diffInDays(now());

        return $days >= $threshold ? $days : null;
    }

    /**
     * @return Builder<Grant>
     */
    private function grants(?string $organizationId): Builder
    {
        $query = Grant::query()->active();
        if ($organizationId !== null) {
            $query->where('organization_id', $organizationId);
        }

        return $query;
    }

    private function threshold(string $key, int $default): int
    {
        $value = config('iam-governance.least_privilege.'.$key, $default);

        return is_int($value) ? $value : $default;
    }

    /**
     * @return array<array-key, mixed>
     */
    private function arr(mixed $value): array
    {
        return is_array($value) ? $value : [];
    }
}
