<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * private_key_jwt (RFC 7523 / OIDC core §9): asymmetric client authentication with NO shared secret.
 * The client keeps a private key and registers its PUBLIC key set (JWKS) here; at the token endpoint it
 * proves possession by signing a short-lived assertion. `token_endpoint_auth_method` selects the method
 * (null/absent = the classic client_secret_* path, unchanged).
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('iam_oauth_clients', function (Blueprint $t): void {
            // The client's PUBLIC JWKS ({"keys":[...]}) — used to verify its client_assertion signature.
            $t->json('jwks')->nullable()->after('secret');
            // 'client_secret_basic' | 'client_secret_post' | 'private_key_jwt' | 'none'. Null → legacy secret.
            $t->string('token_endpoint_auth_method')->nullable()->after('jwks');
        });
    }

    public function down(): void
    {
        Schema::table('iam_oauth_clients', function (Blueprint $t): void {
            $t->dropColumn(['jwks', 'token_endpoint_auth_method']);
        });
    }
};
