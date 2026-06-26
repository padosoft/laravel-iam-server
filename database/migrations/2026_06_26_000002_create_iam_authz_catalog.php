<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/*
 * M2 — Authorization catalog: permissions, roles, role_permissions.
 * + policy_version su iam_organizations (consistency token / zookie-like, doc 09 §6).
 * Slug immutabili (ADR-0019): full_key = app_key:key.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('iam_permissions', function (Blueprint $t): void {
            $t->ulid('id')->primary();
            $t->string('app_key')->nullable();          // null = namespace core iam:
            $t->string('key');                          // es. stock.adjust
            $t->string('full_key')->unique();           // app_key:key (immutabile)
            $t->string('resource')->nullable();
            $t->string('action')->nullable();
            $t->string('risk')->default('low');         // low|medium|high|critical
            $t->boolean('requires_step_up')->default(false);
            $t->timestamp('deprecated_at')->nullable();
            $t->timestamps();
        });

        Schema::create('iam_roles', function (Blueprint $t): void {
            $t->ulid('id')->primary();
            $t->string('app_key')->nullable();
            $t->string('key');
            $t->string('full_key')->unique();
            $t->string('label')->nullable();
            $t->boolean('is_privileged')->default(false);
            $t->timestamp('deprecated_at')->nullable();
            $t->timestamps();
        });

        Schema::create('iam_role_permissions', function (Blueprint $t): void {
            // Pivot puro: chiave composita (attach() non popola una PK ULID separata).
            $t->foreignUlid('role_id')->constrained('iam_roles')->cascadeOnDelete();
            $t->foreignUlid('permission_id')->constrained('iam_permissions')->cascadeOnDelete();
            $t->primary(['role_id', 'permission_id']);
        });

        Schema::table('iam_organizations', function (Blueprint $t): void {
            // consistency token: incrementato a ogni mutazione di authz (grant/role/policy).
            $t->unsignedBigInteger('policy_version')->default(1);
        });
    }

    public function down(): void
    {
        Schema::table('iam_organizations', function (Blueprint $t): void {
            $t->dropColumn('policy_version');
        });
        Schema::dropIfExists('iam_role_permissions');
        Schema::dropIfExists('iam_roles');
        Schema::dropIfExists('iam_permissions');
    }
};
