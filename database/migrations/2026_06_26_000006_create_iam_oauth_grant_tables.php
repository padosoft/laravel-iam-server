<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/*
 * M4b — Tabelle di supporto ai grant Authorization Code + Refresh Token (doc 13 §6).
 * league gestisce la state-machine; qui persistiamo solo gli identificativi per
 * revoca e (M4b.3) replay detection sui refresh token.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('iam_oauth_auth_codes', function (Blueprint $t): void {
            $t->ulid('id')->primary();
            $t->string('auth_code_id')->unique();        // identificativo league del code
            $t->string('client_id');
            $t->string('user_id')->nullable();
            $t->json('scopes')->nullable();
            $t->string('nonce')->nullable();             // OIDC: legato all'id_token (anti-replay)
            $t->timestamp('auth_time')->nullable();      // OIDC: istante di autenticazione del subject
            $t->boolean('revoked')->default(false);
            $t->timestamp('expires_at')->nullable();
            $t->timestamps();

            $t->index('client_id');
        });

        Schema::create('iam_oauth_refresh_tokens', function (Blueprint $t): void {
            $t->ulid('id')->primary();
            $t->string('refresh_token_id')->unique();    // identificativo league del refresh token
            $t->string('chain_id');                      // famiglia di rotazione (replay → revoca catena, RFC 9700)
            $t->string('access_token_jti');              // access token associato (revoca a cascata)
            $t->boolean('revoked')->default(false);
            $t->timestamp('expires_at')->nullable();
            $t->timestamps();

            $t->index('chain_id');
            $t->index('access_token_jti');
        });

        // Stato a livello di CATENA: una volta compromessa (replay rilevato), ogni token
        // della famiglia — anche quelli emessi concorrentemente DOPO la rilevazione — è invalido.
        // Il lock su questa riga serializza emissione e revoca, chiudendo la race "token figlio
        // sfugge allo snapshot" (RFC 9700 §4.14.2).
        Schema::create('iam_oauth_token_chains', function (Blueprint $t): void {
            $t->string('chain_id')->primary();
            $t->boolean('compromised')->default(false);
            $t->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('iam_oauth_token_chains');
        Schema::dropIfExists('iam_oauth_refresh_tokens');
        Schema::dropIfExists('iam_oauth_auth_codes');
    }
};
