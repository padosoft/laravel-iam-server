<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Audit\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * Testa della hash-chain per stream (doc 12 §2.3). La scrittura di un evento la blocca con
 * `lockForUpdate`: due eventi concorrenti sullo stesso stream non possono puntare allo stesso
 * prev_hash. `seq` è il progressivo autoritativo dello stream.
 *
 * @property string $stream
 * @property string|null $hash
 * @property int $seq
 * @property Carbon|null $sealed_at
 */
final class AuditHead extends Model
{
    protected $table = 'iam_audit_heads';

    protected $primaryKey = 'stream';

    public $incrementing = false;

    protected $keyType = 'string';

    public $timestamps = false;

    protected $fillable = ['stream', 'hash', 'seq', 'sealed_at'];

    protected $casts = [
        'seq' => 'integer',
        'sealed_at' => 'datetime',
    ];
}
