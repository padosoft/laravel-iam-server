<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Padosoft\Iam\Domain\OAuth\Models\OauthClient;

uses(RefreshDatabase::class);

// App di tipo `agent` (delega RFC 8693, modulo -agents): validManifest() vive in ApplicationsHelpers.php.

/** @return array<string, mixed> */
function agentManifest(): array
{
    $payload = validManifest();
    $payload['app']['key'] = 'crm-agent';
    $payload['app']['name'] = 'CRM Agent';
    $payload['app']['type'] = 'agent';
    $payload['auth'] = [
        'client_type' => 'confidential',
        'token_endpoint_auth_method' => 'private_key_jwt',
        'jwks' => ['keys' => [['kty' => 'EC', 'crv' => 'P-256', 'kid' => 'agent-key-1', 'x' => 'x', 'y' => 'y']]],
    ];

    return $payload;
}

it('rifiuta app.type agent senza private_key_jwt (nessun shared secret per gli agenti)', function () {
    $payload = agentManifest();
    unset($payload['auth']['token_endpoint_auth_method']);

    expect(manifests()->submit($payload)->status)->toBe('rejected');
});

it('accetta app.type agent con private_key_jwt', function () {
    $manifest = manifests()->submit(agentManifest());

    expect($manifest->validation_errors)->toBeNull()
        ->and($manifest->status)->not->toBe('rejected');
});

it('assegna al client agent SOLO il grant token-exchange (no auth-code, no refresh)', function () {
    submitApproveApply(agentManifest());

    $client = OauthClient::query()->where('client_id', 'cli_crm-agent')->firstOrFail();

    expect($client->grants)->toBe(['urn:ietf:params:oauth:grant-type:token-exchange'])
        ->and($client->token_endpoint_auth_method)->toBe('private_key_jwt')
        ->and($client->is_confidential)->toBeTrue();
});

it('continua a rifiutare un app.type sconosciuto (typo ≠ agent)', function () {
    $payload = agentManifest();
    $payload['app']['type'] = 'agnet';

    expect(manifests()->submit($payload)->status)->toBe('rejected');
});
