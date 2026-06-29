<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Padosoft\Iam\Contracts\Crypto\TokenSigner;
use Padosoft\Iam\Http\Admin\Support\TokenAdminActorResolver;

uses(RefreshDatabase::class);

function requestWithBearer(string $token): Request
{
    return Request::create('/api/iam/v1/users', 'GET', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$token]);
}

it('risolve l\'attore da un access token IAM valido', function () {
    $jwt = app(TokenSigner::class)->issue(['sub' => 'usr_42', 'org' => 'org_acme', 'scope' => 'iam:users.read'], 300);

    $ctx = app(TokenAdminActorResolver::class)->resolve(requestWithBearer($jwt));

    expect($ctx)->not->toBeNull()
        ->and($ctx->actor->id)->toBe('usr_42')
        ->and($ctx->organizationId)->toBe('org_acme')
        ->and($ctx->scopes)->toContain('iam:users.read');
});

it('rifiuta un token assente o malformato', function () {
    $resolver = app(TokenAdminActorResolver::class);

    expect($resolver->resolve(Request::create('/x', 'GET')))->toBeNull()
        ->and($resolver->resolve(requestWithBearer('not-a-jwt')))->toBeNull();
});

it('applica l\'enforcement dell\'audience quando configurata (fail-closed)', function () {
    config(['iam.admin.audience' => 'iam-admin']);
    $signer = app(TokenSigner::class);
    $resolver = app(TokenAdminActorResolver::class);

    $wrong = $signer->issue(['sub' => 'usr_1', 'aud' => 'some-other-app'], 300);
    expect($resolver->resolve(requestWithBearer($wrong)))->toBeNull();

    $right = $signer->issue(['sub' => 'usr_1', 'aud' => 'iam-admin'], 300);
    expect($resolver->resolve(requestWithBearer($right)))->not->toBeNull();
});
