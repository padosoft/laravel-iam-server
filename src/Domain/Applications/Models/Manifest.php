<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Applications\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * Versione di manifest sottomessa per un'app (doc 01 §10). Stato e diff sono gestiti dal motore
 * (validate/diff/apply): fuori da fillable per evitare transizioni di lifecycle non controllate.
 *
 * @property string $id
 * @property string|null $organization_id
 * @property string $application_key
 * @property string $schema
 * @property int $version
 * @property array<string, mixed> $payload
 * @property array<string, mixed>|null $diff
 * @property list<string>|null $validation_errors
 * @property string $status
 * @property bool $requires_approval
 * @property string|null $submitted_by
 * @property string|null $approved_by
 * @property Carbon|null $applied_at
 */
final class Manifest extends Model
{
    use HasUlids;

    protected $table = 'iam_manifests';

    /** @var list<string> status/diff/validation_errors/approval/applied_at via transizioni controllate. */
    protected $fillable = [
        'organization_id', 'application_key', 'schema', 'version', 'payload', 'submitted_by',
    ];

    /** @var array<string, mixed> */
    protected $attributes = [
        'schema' => 'laravel-iam.manifest.v2',
        'status' => 'submitted',
        'requires_approval' => false,
    ];

    protected $casts = [
        'payload' => 'array',
        'diff' => 'array',
        'validation_errors' => 'array',
        'requires_approval' => 'boolean',
        'applied_at' => 'datetime',
    ];
}
