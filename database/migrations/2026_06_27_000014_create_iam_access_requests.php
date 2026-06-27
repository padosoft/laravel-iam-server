<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/*
 * M8.4 — Access Request self-service (doc 14 §4). Il catalogo è default-deny: un ruolo è
 * visibile/richiedibile solo se (1) FeatureScope.access_request è acceso, (2) il richiedente ha
 * iam:access_request.use e (3) il ruolo è marcato `self_requestable` nel manifest + passa la
 * visibility policy. La marcatura (self_requestable + request{}) si materializza su iam_roles
 * dall'apply del manifest. Su approvazione nasce un grant time-boxed (source=access_request).
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('iam_roles', function (Blueprint $t): void {
            $t->boolean('self_requestable')->default(false)->after('is_privileged');
            $t->json('request_json')->nullable()->after('self_requestable'); // visibility/approvers/max_duration/...
        });

        Schema::create('iam_access_requests', function (Blueprint $t): void {
            $t->ulid('id')->primary();
            $t->foreignUlid('organization_id')->nullable()->constrained('iam_organizations')->nullOnDelete();
            $t->string('requester_type')->default('user'); // type del SubjectRef richiedente
            $t->string('requester_id');
            $t->string('application_key');
            $t->string('role_key');                        // full_key del ruolo richiesto
            $t->text('justification')->nullable();
            $t->string('status')->default('pending');      // pending|approved|rejected|expired|cancelled
            $t->json('approver_chain_json')->nullable();   // snapshot degli approver dal manifest
            // Snapshot della request policy del ruolo (max_duration/visibility/...) AL MOMENTO della
            // submit: l'approvazione non dipende dal ruolo ancora esistente/invariato → durata sempre
            // applicata anche se il ruolo viene tolto dal catalogo o modificato dopo la richiesta.
            $t->json('request_policy_json')->nullable();
            $t->timestamp('decided_at')->nullable();
            $t->string('decided_by')->nullable();
            $t->text('decision_note')->nullable();
            $t->string('granted_grant_id')->nullable();    // FK logica al grant creato in approvazione
            $t->timestamps();

            $t->index(['requester_type', 'requester_id', 'status']);
            $t->index(['application_key', 'status']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('iam_access_requests');
        Schema::table('iam_roles', function (Blueprint $t): void {
            $t->dropColumn(['self_requestable', 'request_json']);
        });
    }
};
