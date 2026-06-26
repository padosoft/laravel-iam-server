<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/*
 * M5.4 — Lega la sessione (M5.1) ai token OIDC: l'auth code trasporta sid (per il claim del
 * token, revocabile), acr (AAL → assurance) e amr (metodi di autenticazione) dall'autenticazione
 * fino all'emissione del token (doc 10 §3/§4, doc 13 §5).
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('iam_oauth_auth_codes', function (Blueprint $t): void {
            $t->string('sid')->nullable()->after('user_id');   // sessione (sid)
            $t->string('acr')->nullable()->after('sid');       // AAL corrente
            $t->json('amr')->nullable()->after('acr');         // metodi di autenticazione
        });
    }

    public function down(): void
    {
        Schema::table('iam_oauth_auth_codes', function (Blueprint $t): void {
            $t->dropColumn(['sid', 'acr', 'amr']);
        });
    }
};
