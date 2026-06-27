<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Audit\Pii;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * Legal hold su un soggetto (doc 12 §7): finché non rilasciato, sospende il crypto-shredding GDPR.
 *
 * @property string $id
 * @property string $subject
 * @property string $reason
 * @property Carbon $placed_at
 * @property Carbon|null $released_at
 */
final class LegalHold extends Model
{
    use HasUlids;

    protected $table = 'iam_legal_holds';

    public $timestamps = false;

    protected $fillable = ['subject', 'reason', 'placed_at', 'released_at'];

    protected $casts = [
        'placed_at' => 'datetime',
        'released_at' => 'datetime',
    ];
}
