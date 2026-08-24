<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Iam\Http\Admin\Support\AdminActorResolver;
use Padosoft\Iam\Http\Admin\Support\AdminContext;

uses(RefreshDatabase::class);

// P4: GET /capabilities — il pannello scopre quali moduli opzionali sono attivi SENZA sondare gli
// endpoint gated a colpi di 409. Autenticato, ma senza iam.can (serve al bootstrap del pannello per
// qualsiasi operatore, anche a permessi minimi).

function capBind(): void
{
    app()->bind(AdminActorResolver::class, fn (): AdminActorResolver => new class implements AdminActorResolver
    {
        public function resolve(Request $request): ?AdminContext
        {
            $id = $request->headers->get('X-Test-Auth');

            return is_string($id) && $id !== '' ? new AdminContext(new SubjectRef('user', $id), null) : null;
        }
    });
}

it('richiede autenticazione admin (401 senza credenziali)', function () {
    capBind();
    $this->getJson('/api/iam/v1/capabilities')->assertStatus(401);
});

it('non richiede alcun permesso iam.can: basta un operatore autenticato', function () {
    capBind(); // nessun grant seminato: un operatore a permessi zero deve comunque vedere le capabilities
    $this->getJson('/api/iam/v1/capabilities', ['X-Test-Auth' => 'adm'])
        ->assertOk()
        ->assertJsonPath('data.modules.directory', false)
        ->assertJsonPath('data.features', []);
});

it('un modulo opzionale si dichiara scrivendo iam.capabilities a boot', function () {
    capBind();
    // Il contratto del modulo (es. laravel-iam-agents nel suo service provider):
    config()->set('iam.capabilities.modules.agents', true);
    config()->set('iam.capabilities.features.agents', ['dcr' => false, 'auth_md' => true]);

    $this->getJson('/api/iam/v1/capabilities', ['X-Test-Auth' => 'adm'])
        ->assertOk()
        ->assertJsonPath('data.modules.agents', true)
        ->assertJsonPath('data.modules.directory', false)
        ->assertJsonPath('data.features.agents.dcr', false)
        ->assertJsonPath('data.features.agents.auth_md', true);
});

it('la chiave directory è posseduta dal core: un modulo non può sovrascriverla', function () {
    capBind();
    config()->set('iam.directory.enabled', true);
    config()->set('iam.capabilities.modules.directory', false); // tentativo di override

    $this->getJson('/api/iam/v1/capabilities', ['X-Test-Auth' => 'adm'])
        ->assertOk()
        ->assertJsonPath('data.modules.directory', true);
});
