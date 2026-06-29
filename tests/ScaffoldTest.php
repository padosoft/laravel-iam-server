<?php

declare(strict_types=1);

use Padosoft\Iam\Contracts\Authorization\AuthorizationEngine;
use Padosoft\Iam\Contracts\Crypto\KeyProvider;
use Padosoft\Iam\Contracts\Crypto\SecretCipher;
use Padosoft\Iam\Contracts\Governance\FeatureContext;
use Padosoft\Iam\Contracts\Governance\FeatureKey;
use Padosoft\Iam\Contracts\Governance\FeatureScope;
use Padosoft\Iam\Contracts\Support\SubjectRef;

it('autoloads i contratti core con namespace Padosoft\\Iam', function () {
    expect(interface_exists(FeatureScope::class))->toBeTrue()
        ->and(interface_exists(AuthorizationEngine::class))->toBeTrue()
        ->and(interface_exists(KeyProvider::class))->toBeTrue()
        ->and(interface_exists(SecretCipher::class))->toBeTrue()
        ->and(enum_exists(FeatureKey::class))->toBeTrue();
});

it('SubjectRef è stringabile come type:id', function () {
    expect((string) new SubjectRef('user', 'usr_123'))->toBe('user:usr_123');
});

it('FeatureContext accetta un FeatureKey e scope opzionali', function () {
    $ctx = new FeatureContext(FeatureKey::AccessRequest, applicationKey: 'warehouse');
    expect($ctx->feature)->toBe(FeatureKey::AccessRequest)
        ->and($ctx->applicationKey)->toBe('warehouse');
});
