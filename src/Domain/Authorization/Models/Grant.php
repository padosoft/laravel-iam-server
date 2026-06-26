<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Authorization\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;
use Padosoft\Iam\Domain\Organizations\Models\Organization;

/**
 * Grant canonico (riconcilia doc 09 §9 e doc 14 §2). IGA-ready by design.
 *
 * @property string $id
 * @property string|null $organization_id
 * @property string|null $application_key
 * @property string|null $resource_ref
 * @property string $subject_type
 * @property string $subject_id
 * @property string $privilege_type
 * @property string $privilege_key
 * @property string $effect
 * @property bool $is_privileged
 * @property bool $activation_required
 * @property Carbon|null $activated_at
 */
final class Grant extends Model
{
    use HasUlids;

    protected $table = 'iam_grants';

    /**
     * Mass-assignment esplicito (sicurezza): NIENTE `$guarded = []` su un modello IAM.
     * `identity_hash` è calcolato in booted(), non assegnabile.
     *
     * @var list<string>
     */
    protected $fillable = [
        'organization_id', 'application_key',
        'subject_type', 'subject_id',
        'privilege_type', 'privilege_key',
        'resource_ref', 'conditions_json', 'effect',
        'valid_from', 'valid_until', 'activated_at',
        'source', 'justification', 'approval_ref',
        'is_privileged', 'activation_required', 'last_used_at',
        'created_by', 'revoked_at', 'revoked_by',
    ];

    /** @var array<string, mixed> */
    protected $attributes = [
        'effect' => 'permit',
        'is_privileged' => false,
        'activation_required' => false,
    ];

    protected $casts = [
        'conditions_json' => 'array',
        'is_privileged' => 'bool',
        'activation_required' => 'bool',
        'valid_from' => 'datetime',
        'valid_until' => 'datetime',
        'activated_at' => 'datetime',
        'last_used_at' => 'datetime',
        'revoked_at' => 'datetime',
    ];

    protected static function booted(): void
    {
        // Dedup deterministico: hash dell'identità del grant → unique index (MySQL-safe).
        self::saving(function (Grant $grant): void {
            $grant->setAttribute('identity_hash', hash('sha256', implode('|', [
                $grant->organization_id ?? '',
                $grant->application_key ?? '',
                $grant->subject_type,
                $grant->subject_id,
                $grant->privilege_type,
                $grant->privilege_key,
                $grant->resource_ref ?? '',
                $grant->effect ?? 'permit',
            ])));
        });
    }

    /** @return BelongsTo<Organization, $this> */
    public function organization(): BelongsTo
    {
        return $this->belongsTo(Organization::class, 'organization_id');
    }

    /**
     * Grant ATTIVI: non revocati, dentro la finestra di validità, e — fail-closed —
     * se richiedono attivazione (PIM) devono essere stati attivati (activated_at not null).
     *
     * @param  Builder<Grant>  $query
     */
    public function scopeActive(Builder $query): void
    {
        $query->whereNull('revoked_at')
            ->where(function (Builder $q): void {
                $q->whereNull('valid_from')->orWhere('valid_from', '<=', now());
            })
            ->where(function (Builder $q): void {
                $q->whereNull('valid_until')->orWhere('valid_until', '>=', now());
            })
            ->where(function (Builder $q): void {
                // PIM fail-closed: un grant activation_required conta solo se attivato.
                $q->where('activation_required', false)->orWhereNotNull('activated_at');
            });
    }
}
