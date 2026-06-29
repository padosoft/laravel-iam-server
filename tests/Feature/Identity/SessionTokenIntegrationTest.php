<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Padosoft\Iam\Contracts\Assurance\Aal;
use Padosoft\Iam\Contracts\Crypto\TokenSigner;
use Padosoft\Iam\Contracts\Identity\SessionMeta;
use Padosoft\Iam\Contracts\Identity\SessionRegistry;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Iam\Domain\Identity\Models\User;
use Padosoft\Iam\Domain\Identity\Session\LogoutTokenIssuer;
use Padosoft\Iam\Domain\Identity\Session\SessionStarter;
use Padosoft\Iam\Domain\OAuth\Models\OauthClient;
use Padosoft\Iam\Domain\OAuth\Models\OauthScope;
use Padosoft\Iam\Domain\Organizations\Models\Organization;

uses(RefreshDatabase::class);

it('lega sid all\'access token e acr/amr/sid all\'id_token quando esiste una sessione', function () {
    $org = Organization::query()->create(['key' => 'acme', 'name' => 'Acme']);
    foreach (['openid', 'profile'] as $s) {
        OauthScope::query()->create(['identifier' => $s]);
    }
    OauthClient::register([
        'client_id' => 'cli_oidc',
        'name' => 'OIDC App',
        'grants' => ['authorization_code', 'refresh_token'],
        'scopes' => ['openid', 'profile'],
        'redirect_uris' => [REDIRECT_URI],
        'is_confidential' => false,
        'is_first_party' => true,
        'organization_id' => $org->id,
    ], null);

    $user = new User;
    $user->forceFill(['email' => 'u@acme.test'])->save();
    $session = app(SessionRegistry::class)->start(new SubjectRef('user', $user->id), new SessionMeta(aal: Aal::AAL2));

    $pkce = pkcePair();
    $location = $this->withSession(['iam_sid' => $session->id])->actingAs($user)
        ->get('/oauth/authorize?'.authorizeQuery($pkce['challenge'], [
            'client_id' => 'cli_oidc',
            'scope' => 'openid profile',
        ]))->headers->get('Location') ?? '';

    $token = $this->post('/oauth/token', [
        'grant_type' => 'authorization_code',
        'client_id' => 'cli_oidc',
        'redirect_uri' => REDIRECT_URI,
        'code' => codeFromRedirect($location),
        'code_verifier' => $pkce['verifier'],
    ]);

    $token->assertOk();
    $access = app(TokenSigner::class)->parse($token->json('access_token'));
    $id = app(TokenSigner::class)->parse($token->json('id_token'));

    expect($access['sid'])->toBe($session->id)
        ->and($id['acr'])->toBe('aal2')
        ->and($id['amr'])->toContain('mfa')
        ->and($id['sid'])->toBe($session->id);
});

it('SessionStarter crea la sessione e lega il sid alla sessione Laravel', function () {
    $user = new User;
    $user->forceFill(['email' => 'u@acme.test'])->save();

    $store = app('session.store');
    $store->start();
    $request = Request::create('/login', 'POST');
    $request->setLaravelSession($store);

    $ref = app(SessionStarter::class)->start($user->id, $request, Aal::AAL2);

    expect(app(SessionRegistry::class)->active($ref->id))->toBeTrue()
        ->and($store->get('iam_sid'))->toBe($ref->id);
});

it('LogoutTokenIssuer emette un logout_token valido (sid + events, niente nonce)', function () {
    $jwt = app(LogoutTokenIssuer::class)->issue('sess-123', 'usr-1', 'cli_app');

    $claims = app(TokenSigner::class)->parse($jwt);
    expect($claims['sid'])->toBe('sess-123')
        ->and($claims['sub'])->toBe('usr-1')
        ->and($claims['aud'])->toContain('cli_app')
        ->and($claims)->toHaveKey('events')
        ->and($claims)->not->toHaveKey('nonce');
});
