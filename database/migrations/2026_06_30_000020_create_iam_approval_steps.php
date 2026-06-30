<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/*
 * M17 — Approver chain (doc 19 §9). Estende l'Access Request (M8) con catene multi-step. La catena è
 * un AND sequenziale: lo step k+1 si attiva solo quando k è approvato; un reject su qualunque step →
 * request rejected (fail-closed). Il grant time-boxed nasce SOLO all'approvazione finale (invariante
 * M8 preservata). Una catena a 1 step coincide col comportamento M8.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('iam_approval_steps', function (Blueprint $t): void {
            $t->ulid('id')->primary();
            $t->foreignUlid('access_request_id')->constrained('iam_access_requests')->cascadeOnDelete();
            $t->unsignedSmallInteger('position');      // ordine nella catena (1,2,3…)
            $t->string('approver_type');               // user | group | role
            $t->string('approver_ref');
            $t->string('status')->default('pending');  // pending | approved | rejected | skipped
            $t->string('decided_by')->nullable();
            $t->timestamp('decided_at')->nullable();
            $t->text('note')->nullable();
            $t->timestamps();

            $t->unique(['access_request_id', 'position']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('iam_approval_steps');
    }
};
