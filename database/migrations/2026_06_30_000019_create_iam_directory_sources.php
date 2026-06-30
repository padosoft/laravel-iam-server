<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/*
 * M17 — Directory Sources (doc 19 §5). Config delle sorgenti LDAP/AD consumate dal modulo `-directory`.
 * Il server possiede solo la CONFIG (questa tabella); sync/test sono delegati al modulo (async via
 * outbox). `bind_secret_encrypted` è l'envelope SecretCipher (M3) del segreto di bind: write-only, mai
 * restituito in chiaro. Se il modulo `-directory` non è attivo, i trigger sync/test rispondono 409.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('iam_directory_sources', function (Blueprint $t): void {
            $t->ulid('id')->primary();
            $t->foreignUlid('organization_id')->nullable()->constrained('iam_organizations')->nullOnDelete();
            $t->string('key');                              // slug stabile (es. corp-ad)
            $t->string('name');
            $t->string('type')->default('ldap');            // ldap | scim(v2) | saml(v2)
            $t->string('host');
            $t->string('base_dn');
            $t->string('bind_dn')->nullable();
            $t->json('bind_secret_encrypted')->nullable();  // envelope SecretCipher (M3), write-only
            $t->json('filters')->nullable();                // user/group filter LDAP
            $t->string('group_mapping_ref')->nullable();    // riferimento alla mappatura gruppi
            $t->string('sync_mode')->default('jit');        // jit | scheduled
            $t->string('status')->default('active');        // active | disabled
            $t->string('last_sync_status')->nullable();     // queued | running | completed | failed
            $t->timestamp('last_sync_at')->nullable();
            $t->timestamps();

            $t->unique(['organization_id', 'key']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('iam_directory_sources');
    }
};
