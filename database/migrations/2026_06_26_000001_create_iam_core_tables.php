<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/*
 * M1 — Core DB: identity, organizations, memberships, grants.
 * Schema CANONICO che riconcilia doc 09 §9 e doc 14 §2 ("cucitura #2"):
 * adottiamo i nomi a KEY (privilege_key, resource_ref, application_key) perché
 * gli slug sono immutabili (ADR-0019) e più stabili degli id FK.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('iam_users', function (Blueprint $t): void {
            $t->ulid('id')->primary();
            $t->string('status')->default('active'); // active|suspended|deactivated
            $t->string('email')->nullable();
            $t->timestamp('email_verified_at')->nullable();
            $t->string('name')->nullable();
            $t->ulid('primary_identity_id')->nullable();
            $t->timestamps();
            $t->unique('email');
        });

        Schema::create('iam_user_status_changes', function (Blueprint $t): void {
            $t->ulid('id')->primary();
            $t->foreignUlid('user_id')->constrained('iam_users')->cascadeOnDelete();
            $t->string('from_status')->nullable();
            $t->string('to_status');
            $t->string('source')->nullable();
            $t->string('reason')->nullable();
            $t->string('actor_ref')->nullable();
            $t->timestamp('occurred_at');
            $t->timestamps();
        });

        Schema::create('iam_organizations', function (Blueprint $t): void {
            $t->ulid('id')->primary();
            $t->string('key')->unique();
            $t->string('name');
            $t->string('status')->default('active'); // active|suspended
            $t->json('metadata')->nullable();
            $t->timestamps();
        });

        Schema::create('iam_memberships', function (Blueprint $t): void {
            $t->ulid('id')->primary();
            $t->foreignUlid('organization_id')->constrained('iam_organizations')->cascadeOnDelete();
            $t->foreignUlid('user_id')->constrained('iam_users')->cascadeOnDelete();
            $t->string('status')->default('active'); // active|invited|suspended|removed
            $t->string('source')->nullable();
            $t->timestamp('joined_at')->nullable();
            $t->timestamp('removed_at')->nullable();
            $t->timestamps();
            $t->unique(['organization_id', 'user_id']);
        });

        Schema::create('iam_grants', function (Blueprint $t): void {
            $t->ulid('id')->primary();
            $t->foreignUlid('organization_id')->nullable()->constrained('iam_organizations')->cascadeOnDelete();
            $t->string('application_key')->nullable();
            $t->string('subject_type'); // user|group|service_account|external_group|agent
            $t->string('subject_id');
            $t->string('privilege_type'); // role|permission|relation
            $t->string('privilege_key');  // es. warehouse:stock_operator (slug immutabile)
            $t->string('resource_ref')->nullable(); // scope/risorsa (FGA-ready)
            $t->json('conditions_json')->nullable(); // ABAC
            $t->string('effect')->default('permit'); // permit|deny
            $t->char('identity_hash', 64)->nullable(); // dedup deterministico (Grant::booted)
            // --- IGA-ready (da v1) ---
            $t->timestamp('valid_from')->nullable();
            $t->timestamp('valid_until')->nullable();
            $t->string('source')->nullable();
            $t->text('justification')->nullable();
            $t->string('approval_ref')->nullable();
            $t->boolean('is_privileged')->default(false);
            $t->boolean('activation_required')->default(false);
            $t->timestamp('activated_at')->nullable(); // PIM: quando il grant è stato attivato
            $t->timestamp('last_used_at')->nullable();
            $t->string('created_by')->nullable();
            $t->timestamp('revoked_at')->nullable();
            $t->string('revoked_by')->nullable();
            $t->timestamps();

            $t->index(['subject_type', 'subject_id']);
            $t->index(['application_key', 'privilege_key']);
            $t->index('organization_id');
            $t->unique('identity_hash', 'iam_grants_identity_unique');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('iam_grants');
        Schema::dropIfExists('iam_memberships');
        Schema::dropIfExists('iam_organizations');
        Schema::dropIfExists('iam_user_status_changes');
        Schema::dropIfExists('iam_users');
    }
};
