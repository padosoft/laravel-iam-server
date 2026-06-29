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
 * Tupla ReBAC `(subject, relation, object)` (doc 18 §5). Sorgente di verità delle relazioni del
 * motore nativo. Tenant-scoped fail-closed; dedup deterministico via identity_hash.
 *
 * @property string $id
 * @property string|null $organization_id
 * @property string $subject_type
 * @property string $subject_id
 * @property string $relation
 * @property string $object_type
 * @property string $object_id
 * @property array<string, mixed>|null $condition
 * @property int $consistency_token
 * @property string|null $created_by
 * @property Carbon|null $revoked_at
 */
final class Relation extends Model
{
    use HasUlids;

    protected $table = 'iam_relations';

    /**
     * Mass-assignment esplicito (sicurezza): niente $guarded = [] su un modello IAM.
     * identity_hash è calcolato in booted(); consistency_token/revoked_at li imposta il RelationWriter.
     *
     * @var list<string>
     */
    protected $fillable = [
        'organization_id',
        'subject_type', 'subject_id',
        'relation',
        'object_type', 'object_id',
        'condition',
        'created_by',
    ];

    protected $casts = [
        'condition' => 'array',
        'consistency_token' => 'integer',
        'revoked_at' => 'datetime',
    ];

    protected static function booted(): void
    {
        // Dedup deterministico: hash dell'identità della tupla → unique index.
        // json_encode (non implode): serializzazione non ambigua → niente separator injection.
        self::saving(function (Relation $relation): void {
            $relation->setAttribute('identity_hash', hash('sha256', json_encode([
                $relation->organization_id,
                $relation->subject_type,
                $relation->subject_id,
                $relation->relation,
                $relation->object_type,
                $relation->object_id,
            ], JSON_THROW_ON_ERROR)));
        });
    }

    /** @return BelongsTo<Organization, $this> */
    public function organization(): BelongsTo
    {
        return $this->belongsTo(Organization::class, 'organization_id');
    }

    /**
     * Revoca la tupla — unico modo per valorizzare revoked_at (simmetrico a Grant::revoke()).
     */
    public function revoke(): void
    {
        $this->forceFill(['revoked_at' => now()])->save();
    }

    /**
     * Tuple ATTIVE: non revocate. Fail-closed by default.
     *
     * @param  Builder<Relation>  $query
     */
    public function scopeActive(Builder $query): void
    {
        $query->whereNull('revoked_at');
    }
}
