<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Padosoft\Iam\Contracts\Governance\FeatureContext;
use Padosoft\Iam\Contracts\Governance\FeatureKey;
use Padosoft\Iam\Contracts\Governance\FeatureScope;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Iam\Domain\Authorization\Models\Grant;

uses(RefreshDatabase::class);

function scope(): FeatureScope
{
    return app(FeatureScope::class);
}

it('default-deny: una feature con default off è spenta', function () {
    config()->set('iam-governance.features.access_request', ['default' => 'off']);

    expect(scope()->isEnabled(new FeatureContext(FeatureKey::AccessRequest)))->toBeFalse();
});

it('default on: una feature con default on è accesa', function () {
    config()->set('iam-governance.features.access_review', ['default' => 'on']);

    expect(scope()->isEnabled(new FeatureContext(FeatureKey::AccessReview)))->toBeTrue();
});

it('override per-app accende una feature spenta di default solo per quell\'app', function () {
    config()->set('iam-governance.features.access_request', [
        'default' => 'off',
        'apps' => ['warehouse' => ['enabled' => 'on']],
    ]);

    expect(scope()->isEnabled(new FeatureContext(FeatureKey::AccessRequest, applicationKey: 'warehouse')))->toBeTrue()
        ->and(scope()->isEnabled(new FeatureContext(FeatureKey::AccessRequest, applicationKey: 'billing')))->toBeFalse();
});

it('vince il livello più specifico esplicito (user override batte app)', function () {
    config()->set('iam-governance.features.pim', [
        'default' => 'off',
        'apps' => ['billing' => ['enabled' => 'on']],
        'users' => ['user:usr_9' => ['enabled' => 'off']],
    ]);

    $ctxApp = new FeatureContext(FeatureKey::Pim, applicationKey: 'billing');
    $ctxUser = new FeatureContext(FeatureKey::Pim, applicationKey: 'billing', subject: new SubjectRef('user', 'usr_9'));

    expect(scope()->isEnabled($ctxApp))->toBeTrue()        // app on
        ->and(scope()->isEnabled($ctxUser))->toBeFalse();  // user override off vince
});

it('mode() risolve la modalità per-scope (SoD detect→enforce sull\'app critica)', function () {
    config()->set('iam-governance.features.sod', [
        'default' => 'detect',
        'apps' => ['billing' => ['mode' => 'enforce']],
    ]);

    expect(scope()->mode(new FeatureContext(FeatureKey::SoD)))->toBe('detect')
        ->and(scope()->mode(new FeatureContext(FeatureKey::SoD, applicationKey: 'billing')))->toBe('enforce');
});

it('isPermitted fa da gate sul permesso configurato (via PDP)', function () {
    config()->set('iam-governance.features.access_request', [
        'default' => 'on',
        'permission' => 'iam:access_request.use',
    ]);

    $actor = new SubjectRef('user', 'usr_5');
    $ctx = new FeatureContext(FeatureKey::AccessRequest, applicationKey: 'iam', subject: $actor);

    expect(scope()->isPermitted($ctx, $actor))->toBeFalse(); // nessun grant → deny

    Grant::create([
        'subject_type' => 'user', 'subject_id' => 'usr_5',
        'privilege_type' => 'permission', 'privilege_key' => 'iam:access_request.use',
        'application_key' => 'iam',
    ]);

    expect(scope()->isPermitted($ctx, $actor))->toBeTrue();
});

it('senza permesso configurato non c\'è gate (isPermitted = true)', function () {
    config()->set('iam-governance.features.least_privilege', ['default' => 'on']);

    expect(scope()->isPermitted(
        new FeatureContext(FeatureKey::LeastPrivilege),
        new SubjectRef('user', 'whoever'),
    ))->toBeTrue();
});
