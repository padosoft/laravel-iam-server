<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/*
 * M17 — Groups (doc 19 §3). Gruppi first-class come soggetti di grant e tuple ReBAC (nesting con M16).
 * Una membership scrive ANCHE la tupla ReBAC `member` (subject=membro, object=group:<key>) via
 * RelationWriter, così membership e nesting restano una single source coerente per il resolver nativo.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('iam_groups', function (Blueprint $t): void {
            $t->ulid('id')->primary();
            $t->foreignUlid('organization_id')->constrained('iam_organizations')->cascadeOnDelete();
            $t->string('key');                       // slug stabile (es. eng, finance)
            $t->string('name');
            $t->string('source')->default('manual'); // manual | directory | scim(v2)
            $t->timestamp('revoked_at')->nullable();
            $t->timestamps();

            $t->unique(['organization_id', 'key']);
        });

        Schema::create('iam_group_members', function (Blueprint $t): void {
            $t->ulid('id')->primary();
            $t->foreignUlid('group_id')->constrained('iam_groups')->cascadeOnDelete();
            $t->string('member_type'); // user | group (nesting) | service_account
            $t->string('member_id');
            $t->timestamps();

            $t->unique(['group_id', 'member_type', 'member_id']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('iam_group_members');
        Schema::dropIfExists('iam_groups');
    }
};
