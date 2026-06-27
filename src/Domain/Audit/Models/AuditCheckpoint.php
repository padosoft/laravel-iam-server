<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Audit\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * Checkpoint firmato della testa di uno stream (doc 12 §2.2). `signature` è un JWT ES256 (firmato
 * dal TokenSigner dell'IAM) che lega stream/up_to_seq/head_hash: verificabile contro il JWKS.
 *
 * @property string $id
 * @property string $stream
 * @property int $up_to_seq
 * @property string $head_hash
 * @property string $signature
 * @property Carbon $signed_at
 * @property Carbon|null $anchored_at
 */
final class AuditCheckpoint extends Model
{
    use HasUlids;

    protected $table = 'iam_audit_checkpoints';

    public $timestamps = false;

    protected $fillable = ['stream', 'up_to_seq', 'head_hash', 'signature', 'signed_at', 'anchored_at'];

    protected $casts = [
        'up_to_seq' => 'integer',
        'signed_at' => 'datetime',
        'anchored_at' => 'datetime',
    ];
}
