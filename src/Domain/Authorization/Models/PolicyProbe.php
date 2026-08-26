<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Authorization\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use Illuminate\Support\Str;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Iam\Domain\Authorization\Pdp\DecisionQuery;
use Padosoft\Iam\Domain\Authorization\Pdp\ResourceRef;

/**
 * Una **sonda di policy**: una domanda di autorizzazione concreta — questo
 * soggetto, questo permesso, questa risorsa — che vale la pena continuare a
 * fare.
 *
 * Serve a due cose che sembrano una sola e non lo sono:
 *
 *  - **blast radius**: date N sonde e una modifica proposta, quante decisioni
 *    cambiano e quali. Qui `expected_allowed` può essere null: la sonda descrive
 *    un caso da osservare, non una promessa.
 *  - **regressione**: `expected_allowed` valorizzato trasforma la sonda in
 *    un'asserzione ("il CFO DEVE poter leggere payroll"), e una divergenza
 *    fallisce la CI prima che il cambio arrivi in produzione.
 *
 * `source` distingue una sonda scritta da un umano da una campionata dal
 * traffico reale: un corpus fatto solo di sonde scritte a mano copre ciò a cui
 * qualcuno ha pensato, uno fatto solo di traffico copre ciò che è già successo.
 * Servono entrambi, e vanno letti sapendo quale è quale.
 *
 * @property string $id
 * @property string|null $organization_id
 * @property string|null $application_key
 * @property string $subject_type
 * @property string $subject_id
 * @property string $permission
 * @property string|null $resource_ref
 * @property array<string, mixed>|null $context
 * @property string $current_aal
 * @property bool|null $expected_allowed
 * @property string $source
 * @property string|null $label
 * @property string $probe_hash
 * @property Carbon|null $last_seen_at
 */
final class PolicyProbe extends Model
{
    public const SOURCE_MANUAL = 'manual';

    public const SOURCE_RECORDED = 'recorded';

    protected $table = 'iam_policy_probes';

    protected $keyType = 'string';

    public $incrementing = false;

    protected $fillable = [
        'id', 'organization_id', 'application_key', 'subject_type', 'subject_id', 'permission',
        'resource_ref', 'context', 'current_aal', 'expected_allowed',
        'source', 'label', 'probe_hash', 'last_seen_at',
    ];

    protected $casts = [
        'context' => 'array',
        'expected_allowed' => 'boolean',
        'last_seen_at' => 'datetime',
    ];

    public static function newId(): string
    {
        return 'prb_'.Str::ulid()->toBase32();
    }

    /**
     * Il digest che identifica la sonda. Il contesto entra con le chiavi ordinate:
     * due sonde identiche scritte con le chiavi in ordine diverso sono la stessa
     * sonda, e trattarle come due riempirebbe il corpus di doppioni.
     *
     * @param  array<string, mixed>  $context
     */
    public static function hashOf(
        SubjectRef $subject,
        string $permission,
        ?string $resourceRef,
        array $context = [],
        ?string $organizationId = null,
        string $currentAal = 'aal1',
        ?string $applicationKey = null,
    ): string {
        ksort($context);

        return 'sha256:'.hash('sha256', json_encode([
            'subject' => (string) $subject,
            'permission' => $permission,
            'resource' => $resourceRef,
            'context' => $context,
            'organization' => $organizationId,
            'application' => $applicationKey,
            'aal' => $currentAal,
        ], JSON_THROW_ON_ERROR));
    }

    /**
     * La sonda come domanda per il PDP.
     *
     * `explain: true` è deliberato: quando una decisione RIBALTA, la domanda
     * successiva è sempre "perché", e senza la spiegazione il report direbbe
     * soltanto che qualcosa è cambiato.
     */
    public function toQuery(bool $explain = true): DecisionQuery
    {
        $object = null;
        if (is_string($this->resource_ref) && str_contains($this->resource_ref, ':')) {
            [$type, $id] = explode(':', $this->resource_ref, 2);
            $object = $type !== '' && $id !== '' ? new ResourceRef($type, $id) : null;
        }

        return new DecisionQuery(
            subject: new SubjectRef($this->subject_type, $this->subject_id),
            permission: $this->permission,
            organizationId: $this->organization_id,
            applicationKey: $this->application_key,
            resourceRef: $this->resource_ref,
            context: $this->context ?? [],
            currentAal: $this->current_aal,
            explain: $explain,
            object: $object,
        );
    }

    /**
     * @return array{id: string, subject: string, permission: string, resource: string|null, organization_id: string|null, application_key: string|null, expected_allowed: bool|null, source: string, label: string|null}
     */
    public function describe(): array
    {
        return [
            'id' => $this->id,
            'subject' => $this->subject_type.':'.$this->subject_id,
            'permission' => $this->permission,
            'resource' => $this->resource_ref,
            'organization_id' => $this->organization_id,
            'application_key' => $this->application_key,
            'expected_allowed' => $this->expected_allowed,
            'source' => $this->source,
            'label' => $this->label,
        ];
    }
}
