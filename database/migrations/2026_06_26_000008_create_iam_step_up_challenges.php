<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/*
 * M5 — Challenge di step-up (doc 10 §4). Emesse quando il PDP richiede `requires_step_up`;
 * single-use (consumed_at) e a scadenza breve. Alla verifica elevano l'AAL della sessione.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('iam_step_up_challenges', function (Blueprint $t): void {
            $t->ulid('id')->primary();
            $t->foreignUlid('session_id')->constrained('iam_sessions')->cascadeOnDelete();
            $t->string('user_id');
            $t->string('action');                 // azione critica che ha richiesto lo step-up
            $t->string('required_aal');           // aal2 | aal3
            $t->string('method');                 // totp | passkey
            $t->timestamp('expires_at');
            $t->timestamp('consumed_at')->nullable();
            $t->timestamps();

            $t->index(['session_id', 'consumed_at']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('iam_step_up_challenges');
    }
};
