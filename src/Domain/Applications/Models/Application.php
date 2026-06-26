<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Applications\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;

/**
 * App registrata nel registry (doc 01 §10). `key` è uno slug IMMUTABILE. Lo stato applicato
 * (permessi/ruoli/client) deriva dal manifest corrente.
 *
 * @property string $id
 * @property string|null $organization_id
 * @property string $key
 * @property string $name
 * @property string $type
 * @property string $risk_level
 * @property string $status
 * @property string|null $current_manifest_id
 */
final class Application extends Model
{
    use HasUlids;

    protected $table = 'iam_applications';

    /** @var list<string> `status` fuori da fillable (transizioni controllate); `key` immutabile (vedi booted). */
    protected $fillable = [
        'organization_id', 'key', 'name', 'type', 'risk_level', 'current_manifest_id',
    ];

    /** @var array<string, mixed> */
    protected $attributes = [
        'type' => 'laravel',
        'risk_level' => 'low',
        'status' => 'active',
    ];

    protected static function booted(): void
    {
        self::updating(function (Application $app): void {
            if ($app->isDirty('key')) {
                throw new \RuntimeException('Application.key è immutabile.');
            }
        });
    }

    public function changeStatus(string $status): void
    {
        $this->forceFill(['status' => $status])->save();
    }
}
