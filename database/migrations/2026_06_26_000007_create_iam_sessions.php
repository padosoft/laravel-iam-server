<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/*
 * M5 — Session registry server-side (doc 10 §3). Ogni sessione è revocabile e legata ai token
 * via `sid` (= id). Idle timeout (last_activity_at) + absolute timeout (mai esteso). AAL corrente
 * + step_up_at per le finestre di step-up. Identificatori device/IP/UA solo come hash (privacy).
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('iam_sessions', function (Blueprint $t): void {
            $t->ulid('id')->primary();                  // sid
            $t->foreignUlid('user_id')->constrained('iam_users')->cascadeOnDelete();
            $t->foreignUlid('organization_id')->nullable()->constrained('iam_organizations')->nullOnDelete();
            $t->string('aal')->default('aal1');         // aal1 | aal2 | aal3
            $t->unsignedInteger('idle_timeout');        // finestra idle (secondi), per-sessione
            $t->timestamp('last_activity_at');          // idle timeout
            $t->timestamp('absolute_expires_at');       // tetto massimo (non estendibile)
            $t->timestamp('step_up_at')->nullable();    // ultimo step-up riuscito
            $t->string('device_fingerprint_hash')->nullable();
            $t->string('ip_hash')->nullable();
            $t->string('user_agent_hash')->nullable();
            $t->timestamp('revoked_at')->nullable();
            $t->string('revoked_reason')->nullable();
            $t->timestamps();

            $t->index(['user_id', 'revoked_at']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('iam_sessions');
    }
};
