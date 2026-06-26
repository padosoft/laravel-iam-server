<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/*
 * M4b — Client store OAuth + scope catalog + token ledger.
 *
 * In v1 il client store è una tabella minimale; in M6 l'Application Registry
 * (manifest-driven) ne diventa il proprietario (doc 13 §4, doc 08 §8). Le
 * state-machine dei grant restano a league/oauth2-server: qui teniamo solo le
 * fonti dati (client, scope) e il ledger dei token per introspection/revoca.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('iam_oauth_clients', function (Blueprint $t): void {
            $t->ulid('id')->primary();
            $t->string('client_id')->unique();           // identificativo pubblico (cli_xxx)
            $t->string('name');
            $t->string('secret')->nullable();            // hash del secret (solo client confidential)
            $t->json('redirect_uris')->nullable();       // URI esatte ammesse (no wildcard)
            $t->json('grants');                          // grant ammessi: client_credentials|authorization_code|refresh_token
            $t->json('scopes')->nullable();              // scope ammessi (subset del catalogo)
            $t->boolean('is_confidential')->default(true);
            // Secure-by-default: un client è third-party (consenso esplicito) finché non è
            // marcato esplicitamente first-party. Mai concedere consenso implicito per omissione.
            $t->boolean('is_first_party')->default(false); // first-party → consenso implicito (doc 13 §7)
            $t->foreignUlid('organization_id')->nullable()->constrained('iam_organizations')->nullOnDelete();
            $t->string('application_key')->nullable();    // link all'Application Registry (M6)
            $t->timestamp('revoked_at')->nullable();
            $t->timestamps();

            $t->index('organization_id');
            $t->index('application_key');
        });

        Schema::create('iam_oauth_scopes', function (Blueprint $t): void {
            $t->ulid('id')->primary();
            $t->string('identifier')->unique();          // es. stock.read, openid, profile
            $t->string('description')->nullable();
            $t->timestamps();
        });

        Schema::create('iam_oauth_access_tokens', function (Blueprint $t): void {
            $t->ulid('id')->primary();
            $t->string('jti')->unique();                 // identificativo del token (= jti del JWT)
            $t->string('client_id');                     // client_id OAuth (cli_xxx)
            $t->string('user_id')->nullable();           // null per client_credentials
            $t->json('scopes')->nullable();
            $t->boolean('revoked')->default(false);
            $t->timestamp('expires_at')->nullable();
            $t->timestamps();

            $t->index('client_id');
            $t->index('user_id');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('iam_oauth_access_tokens');
        Schema::dropIfExists('iam_oauth_scopes');
        Schema::dropIfExists('iam_oauth_clients');
    }
};
