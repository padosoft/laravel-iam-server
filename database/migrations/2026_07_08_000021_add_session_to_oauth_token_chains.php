<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * IAM-11: lega la catena di refresh token alla sessione server-side. Persistendo sid/acr/amr sulla
 * catena, il refresh grant può (a) NEGARE il refresh quando la sessione è stata revocata e (b) RIPORTARE
 * sid/acr/amr sugli access token ruotati, così il binding sessione↔token sopravvive alla rotazione.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('iam_oauth_token_chains', function (Blueprint $t): void {
            $t->string('sid')->nullable()->after('auth_time');   // sessione server-side d'origine
            $t->string('acr')->nullable()->after('sid');         // authentication context class reference
            $t->json('amr')->nullable()->after('acr');           // authentication methods references
        });
    }

    public function down(): void
    {
        Schema::table('iam_oauth_token_chains', function (Blueprint $t): void {
            $t->dropColumn(['sid', 'acr', 'amr']);
        });
    }
};
