<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/*
 * M6 — Application Registry + Manifest engine (doc 01 §10). Ogni app si registra via manifest
 * versionato (schema laravel-iam.manifest.v2). Il manifest dichiara app+auth(client)+permissions+
 * roles+resource/scope/condition types; il lifecycle è submitted→validated→diffed→pending_approval
 * →approved→applied (reject/rolled_back/deprecated). L'app key è uno slug IMMUTABILE (ADR-0019).
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('iam_applications', function (Blueprint $t): void {
            $t->ulid('id')->primary();
            $t->foreignUlid('organization_id')->nullable()->constrained('iam_organizations')->nullOnDelete();
            $t->string('key')->unique();                 // slug immutabile (es. warehouse)
            $t->string('name');
            $t->string('type')->default('laravel');      // laravel | spa | mobile | service
            $t->string('risk_level')->default('low');    // low | medium | high | critical
            $t->string('status')->default('active');     // active | disabled
            $t->string('current_manifest_id')->nullable(); // versione manifest applicata
            $t->timestamps();
        });

        Schema::create('iam_manifests', function (Blueprint $t): void {
            $t->ulid('id')->primary();
            $t->foreignUlid('organization_id')->nullable()->constrained('iam_organizations')->nullOnDelete();
            $t->string('application_key');                // l'app può non esistere ancora al submit
            $t->string('schema')->default('laravel-iam.manifest.v2');
            $t->unsignedInteger('version')->default(1);  // progressivo per app
            $t->json('payload');                          // manifest completo
            $t->json('diff')->nullable();                 // diff calcolato vs stato applicato
            $t->json('validation_errors')->nullable();
            $t->string('status')->default('submitted');
            $t->boolean('requires_approval')->default(false);
            $t->string('submitted_by')->nullable();
            $t->string('approved_by')->nullable();
            $t->timestamp('applied_at')->nullable();
            $t->timestamps();

            $t->index(['application_key', 'status']);
            $t->unique(['application_key', 'version']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('iam_manifests');
        Schema::dropIfExists('iam_applications');
    }
};
