<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Identity\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * Challenge di step-up persistita (doc 10 §4). Single-use, breve durata.
 *
 * @property string $id
 * @property string $session_id
 * @property string $user_id
 * @property string $action
 * @property string $required_aal
 * @property string $method
 * @property Carbon $expires_at
 * @property Carbon|null $consumed_at
 */
final class StepUpChallengeModel extends Model
{
    use HasUlids;

    protected $table = 'iam_step_up_challenges';

    /** @var list<string> consumed_at fuori da fillable: lo scrive solo verify(). */
    protected $fillable = [
        'session_id', 'user_id', 'action', 'required_aal', 'method', 'expires_at',
    ];

    protected $casts = [
        'expires_at' => 'datetime',
        'consumed_at' => 'datetime',
    ];
}
