<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\OAuth\Entities;

use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\RefreshTokenTrait;

/**
 * Refresh token per league (doc 13 §6). La rotation/replay detection vive nel repository (M4b.3).
 */
final class RefreshTokenEntity implements RefreshTokenEntityInterface
{
    use EntityTrait;
    use RefreshTokenTrait;
}
