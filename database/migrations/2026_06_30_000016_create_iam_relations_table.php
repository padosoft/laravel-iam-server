<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Tuple store ReBAC (doc 18 §4, doc 09 §9). Una riga = un fatto `(subject, relation, object)`.
 * Tenant-scoped fail-closed come iam_grants; indici forward/reverse per list-subjects/list-resources.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('iam_relations', function (Blueprint $t): void {
            $t->ulid('id')->primary();
            $t->foreignUlid('organization_id')->nullable()->constrained('iam_organizations')->cascadeOnDelete();
            $t->string('subject_type'); // user|group|service_account|external_group|agent
            $t->string('subject_id');
            $t->string('relation');     // owner|editor|viewer|parent|member|... (slug)
            $t->string('object_type');  // doc|folder|group|... (tipo risorsa applicativa)
            $t->string('object_id');
            $t->json('condition')->nullable();                       // ABAC opzionale (riusa ConditionEvaluator)
            $t->unsignedBigInteger('consistency_token')->default(0); // = policy_version al momento del write
            $t->string('created_by')->nullable();
            $t->char('identity_hash', 64);                           // dedup deterministico (Relation::booted)
            $t->timestamp('revoked_at')->nullable();
            $t->timestamps();

            // Forward: "chi ha relation R su O?" → list-subjects + check (espansione gerarchia)
            $t->index(['object_type', 'object_id', 'relation'], 'iam_rel_forward');
            // Reverse: "su cosa S ha relation R?" → list-resources + check (espansione gruppi)
            $t->index(['subject_type', 'subject_id', 'relation'], 'iam_rel_reverse');
            $t->unique('identity_hash', 'iam_relations_identity_unique');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('iam_relations');
    }
};
