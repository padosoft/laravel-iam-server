<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Crypto\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * Data Encryption Key per-scope (doc 11 §8). Crypto-shredding: `shredded_at` + `wrapped_dek=null`.
 *
 * @property string $id
 * @property string $scope
 * @property string|null $wrapped_dek
 * @property string $key_id
 * @property int $key_version
 * @property Carbon|null $shredded_at
 */
final class DataKey extends Model
{
    use HasUlids;

    protected $table = 'iam_data_keys';

    /** @var list<string> */
    protected $fillable = [
        // 'shredded_at' NON fillable: distruzione GDPR irreversibile, solo via SecretCipher::shred().
        'scope', 'wrapped_dek', 'key_id', 'key_version',
    ];

    protected $casts = [
        'key_version' => 'integer',
        'shredded_at' => 'datetime',
    ];
}
