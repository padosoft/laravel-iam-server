<?php

declare(strict_types=1);

namespace Padosoft\Iam\Http\Admin\Controllers;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Iam\Domain\Applications\Manifest\ManifestRegistry;
use Padosoft\Iam\Domain\Applications\Models\Manifest;
use Padosoft\Iam\Domain\Authorization\Models\PolicyProbe;
use Padosoft\Iam\Domain\Authorization\Simulation\BlastRadiusSimulator;
use Padosoft\Iam\Domain\Authorization\Simulation\PolicyRegressionRunner;
use Padosoft\Iam\Http\Admin\AdminController;
use Padosoft\Iam\Http\Admin\Support\ApiProblemException;

/**
 * Admin API — sonde di policy, blast radius, regressione.
 *
 * **Il blast radius si misura solo su un manifest, mai su una mutazione
 * arbitraria mandata nel body.** Sarebbe la feature più facile da aggiungere e
 * la peggiore: eseguire scritture arbitrarie prese da una richiesta — anche
 * annullandole — significa lock, trigger e carico su tabelle di produzione a
 * comando. Un manifest è già validato, già un artefatto di approvazione, e
 * simularlo è esattamente il momento in cui un revisore vuole sapere cosa farà.
 *
 * Complementare, non alternativo, alla `policies-wizard/preview`: quella misura
 * l'impatto di UN grant che stai componendo; questa misura un cambiamento intero
 * contro il corpus di sonde che l'organizzazione ha deciso di tenere d'occhio.
 */
final class PolicySimulationController extends AdminController
{
    public function __construct(
        private readonly BlastRadiusSimulator $simulator,
        private readonly PolicyRegressionRunner $regression,
        private readonly ManifestRegistry $manifests,
    ) {}

    public function index(Request $request): JsonResponse
    {
        $query = PolicyProbe::query();
        $org = $this->context($request)->organizationId;

        if ($org !== null) {
            $query->where('organization_id', $org);
        }

        if (is_string($source = $request->query('source')) && $source !== '') {
            $query->where('source', $source);
        }

        if ($request->boolean('with_expectation')) {
            $query->whereNotNull('expected_allowed');
        }

        return $this->paginate($query, $request, fn (Model $m): array => $m instanceof PolicyProbe ? $m->describe() : []);
    }

    public function store(Request $request): JsonResponse
    {
        $subject = $this->subject($request);
        $permission = $request->string('permission')->toString();

        if ($permission === '') {
            throw ApiProblemException::unprocessable('permission is required.');
        }

        $resource = $request->string('resource')->toString() ?: null;
        /** @var array<string, mixed> $context */
        $context = is_array($request->input('context')) ? $request->input('context') : [];
        $aal = $request->string('current_aal', 'aal1')->toString();
        $organizationId = $this->context($request)->organizationId ?? ($request->string('organization_id')->toString() ?: null);
        $applicationKey = $request->string('application_key')->toString() ?: null;

        $hash = PolicyProbe::hashOf($subject, $permission, $resource, $context, $organizationId, $aal, $applicationKey);

        // Idempotente sul digest: ri-registrare la stessa sonda deve poter
        // aggiornare l'aspettativa, non creare un doppione che poi diverge.
        $probe = PolicyProbe::query()->firstOrNew(['probe_hash' => $hash]);
        $probe->fill([
            'id' => $probe->exists ? $probe->id : PolicyProbe::newId(),
            'organization_id' => $organizationId,
            'application_key' => $applicationKey,
            'subject_type' => $subject->type,
            'subject_id' => $subject->id,
            'permission' => $permission,
            'resource_ref' => $resource,
            'context' => $context !== [] ? $context : null,
            'current_aal' => $aal,
            'source' => PolicyProbe::SOURCE_MANUAL,
            'label' => $request->string('label')->toString() ?: null,
            'probe_hash' => $hash,
        ]);

        if ($request->has('expected_allowed')) {
            $probe->expected_allowed = $request->boolean('expected_allowed');
        }

        $probe->save();

        $this->audit($request, 'iam.policy.probe.saved', 'policy_probe', $probe->id, $probe->describe());

        return $this->ok($probe->describe(), $probe->wasRecentlyCreated ? 201 : 200);
    }

    public function destroy(Request $request, string $probe): JsonResponse
    {
        $model = PolicyProbe::query()->find($probe);

        if ($model === null) {
            throw ApiProblemException::notFound('Policy probe not found.');
        }

        $described = $model->describe();
        $model->delete();

        $this->audit($request, 'iam.policy.probe.deleted', 'policy_probe', $probe, $described);

        return $this->ok([]);
    }

    /**
     * "Cosa farebbe questo manifest, se lo applicassimo?" — misurato applicandolo
     * davvero in transazione e annullandolo.
     */
    public function blastRadius(Request $request, string $manifest): JsonResponse
    {
        $model = Manifest::query()->find($manifest);
        $org = $this->context($request)->organizationId;

        if ($model === null || ($org !== null && $model->organization_id !== $org)) {
            throw ApiProblemException::notFound('Manifest not found.');
        }

        $probes = $this->probesFor($org);

        if ($probes === []) {
            throw ApiProblemException::unprocessable(
                'No policy probes to measure against. Add probes (or enable sampling) before asking for a blast radius — a report over zero probes would say "no impact" and mean nothing.',
            );
        }

        // Il valore di ritorno dell'apply è deliberatamente scartato: il
        // simulatore misura l'EFFETTO del cambiamento sulle decisioni, e l'oggetto
        // che l'apply restituisce vive dentro una transazione che sta per essere
        // annullata — restituirlo al chiamante significherebbe consegnargli un
        // modello che non esiste più.
        $report = $this->simulator->simulate($probes, function () use ($model): void {
            $this->manifests->apply($model);
        });

        $this->audit($request, 'iam.policy.blast_radius.measured', 'manifest', $model->id, [
            'probes' => count($probes),
            'counts' => $report->counts(),
        ]);

        return $this->ok([
            'manifest_id' => $model->id,
            'application_key' => $model->application_key,
            ...$report->toArray($request->boolean('include_unchanged')),
        ]);
    }

    /**
     * Il corpus di regressione contro lo stato CORRENTE: la policy dice ancora
     * quello che avevamo deciso che dicesse?
     */
    public function regression(Request $request): JsonResponse
    {
        $result = $this->regression->run($this->probesFor($this->context($request)->organizationId));

        return $this->ok($result->toArray(), $result->passed() ? 200 : 422);
    }

    /**
     * @return list<PolicyProbe>
     */
    private function probesFor(?string $organizationId): array
    {
        $query = PolicyProbe::query()->orderBy('id');

        if ($organizationId !== null) {
            $query->where('organization_id', $organizationId);
        }

        /** @var list<PolicyProbe> $probes */
        $probes = array_values($query->limit(1000)->get()->all());

        return $probes;
    }

    private function subject(Request $request): SubjectRef
    {
        $raw = $request->input('subject');

        if (is_array($raw) && is_string($raw['type'] ?? null) && is_string($raw['id'] ?? null)) {
            return new SubjectRef($raw['type'], $raw['id']);
        }

        if (is_string($raw) && str_contains($raw, ':')) {
            [$type, $id] = explode(':', $raw, 2);

            if ($type !== '' && $id !== '') {
                return new SubjectRef($type, $id);
            }
        }

        throw ApiProblemException::unprocessable('subject is required as {type,id} or "type:id".');
    }
}
