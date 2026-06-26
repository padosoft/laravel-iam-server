<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/*
 * M5 — Identità federate (doc 10 §1/§5/§7). Il legame primario è (provider, provider_subject),
 * MAI la sola email (anti account-takeover). Le credenziali/segreti dei provider sono cifrati
 * (SecretCipher di M3). Un conflitto crea un link `pending` che richiede step-up/approval.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('iam_federated_providers', function (Blueprint $t): void {
            $t->ulid('id')->primary();
            $t->foreignUlid('organization_id')->nullable()->constrained('iam_organizations')->nullOnDelete();
            $t->string('key');                              // es. google, github, entra
            $t->string('driver');                           // socialite | oidc | saml
            $t->string('client_id')->nullable();
            $t->text('client_secret_encrypted')->nullable(); // cifrato via SecretCipher (M3)
            $t->string('redirect_uri')->nullable();
            $t->json('scopes')->nullable();
            $t->json('options')->nullable();
            $t->string('auto_link_policy')->default('verified_email'); // verified_email | never
            $t->json('jit_policy')->nullable();
            $t->string('status')->default('active');        // active | disabled
            $t->timestamps();

            $t->unique(['organization_id', 'key']);
        });

        Schema::create('iam_federated_identities', function (Blueprint $t): void {
            $t->ulid('id')->primary();
            $t->foreignUlid('user_id')->nullable()->constrained('iam_users')->cascadeOnDelete();
            $t->foreignUlid('provider_id')->constrained('iam_federated_providers')->cascadeOnDelete();
            $t->string('provider_subject');                 // identificatore stabile presso l'IdP
            $t->string('status')->default('linked');        // linked | pending
            $t->string('email')->nullable();
            $t->boolean('email_verified')->default(false);
            $t->string('display_name')->nullable();
            $t->text('raw_profile_encrypted')->nullable();  // profilo grezzo cifrato (opz.)
            $t->string('pending_reason')->nullable();       // perché il link è pending
            $t->timestamp('linked_at')->nullable();
            $t->timestamp('last_login_at')->nullable();
            $t->timestamp('revoked_at')->nullable();
            $t->timestamps();

            // (provider, provider_subject) è UNICO: l'identità è risolta da qui, non dall'email.
            $t->unique(['provider_id', 'provider_subject']);
            $t->index('user_id');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('iam_federated_identities');
        Schema::dropIfExists('iam_federated_providers');
    }
};
