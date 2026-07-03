<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Padosoft\Iam\Domain\OAuth\Models\OauthClient;
use Padosoft\Iam\Domain\OAuth\Repositories\ClientRepository;

uses(RefreshDatabase::class);

function confidentialClient(string $id, string $secret, array $overrides = []): OauthClient
{
    $c = OauthClient::register(['client_id' => $id, 'name' => $id, 'is_confidential' => true, 'grants' => ['client_credentials']], $secret);
    if ($overrides !== []) {
        $c->forceFill($overrides)->save();
    }

    return $c;
}

it('auto-rotation: il comando ruota solo i client dovuti e archivia il nuovo secret cifrato', function () {
    // Dovuto: auto_rotate, intervallo 30gg, ruotato 31gg fa.
    confidentialClient('cli_due', 'old', ['auto_rotate' => true, 'rotate_interval_days' => 30, 'secret_rotated_at' => now()->subDays(31)]);
    // Non dovuto: auto_rotate ma ruotato ieri.
    confidentialClient('cli_fresh', 'x', ['auto_rotate' => true, 'rotate_interval_days' => 30, 'secret_rotated_at' => now()->subDay()]);
    // Non in auto-rotazione.
    confidentialClient('cli_manual', 'y', ['rotate_interval_days' => 30, 'secret_rotated_at' => now()->subDays(99)]);

    $this->artisan('iam:rotate-due-secrets')->assertSuccessful();

    $due = OauthClient::query()->where('client_id', 'cli_due')->firstOrFail();
    expect($due->secret_pending_encrypted)->not->toBeNull()          // pending cifrato per il self-fetch
        ->and($due->previousSecretActive())->toBeTrue()               // grace aperto
        ->and($due->pendingSecret())->toBeString();                   // decriptabile
    // Il vecchio 'old' resta valido nel grace (rollover).
    expect((new ClientRepository)->validateClient('cli_due', 'old', null))->toBeTrue();

    expect(OauthClient::query()->where('client_id', 'cli_fresh')->firstOrFail()->secret_pending_encrypted)->toBeNull();
    expect(OauthClient::query()->where('client_id', 'cli_manual')->firstOrFail()->secret_pending_encrypted)->toBeNull();
});

it('self-fetch: il client ritira il nuovo secret autenticandosi con quello ancora valido', function () {
    $client = confidentialClient('cli_sf', 'CURRENT');
    $new = $client->rotateSecret(259200, null, storeForPickup: true); // grace 72h; 'CURRENT' → previous

    // L'app si autentica col vecchio (in grace) e ritira il nuovo.
    $res = $this->postJson('/oauth/client-secret', [], ['Authorization' => 'Basic '.base64_encode('cli_sf:CURRENT')])
        ->assertOk();
    expect($res->json('rotated'))->toBeTrue()
        ->and($res->json('client_secret'))->toBe($new);

    // Il nuovo secret autentica (ed è quello che l'app userà dopo lo swap).
    expect((new ClientRepository)->validateClient('cli_sf', $new, null))->toBeTrue();
});

it('self-fetch: senza pending ritorna rotated=false; credenziali errate 401', function () {
    confidentialClient('cli_np', 'S');

    $this->postJson('/oauth/client-secret', [], ['Authorization' => 'Basic '.base64_encode('cli_np:S')])
        ->assertOk()->assertJsonPath('rotated', false);

    $this->postJson('/oauth/client-secret', [], ['Authorization' => 'Basic '.base64_encode('cli_np:WRONG')])
        ->assertStatus(401);
});

it('self-fetch: disabilitato da config è 404', function () {
    config(['iam.oauth.client_selffetch' => false]);
    confidentialClient('cli_off', 'S');

    $this->postJson('/oauth/client-secret', [], ['Authorization' => 'Basic '.base64_encode('cli_off:S')])
        ->assertStatus(404);
});
