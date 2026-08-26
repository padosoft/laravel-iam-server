<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('iam_policy_probes', function (Blueprint $table): void {
            // Id `prb_{ulid}`.
            $table->string('id', 64)->primary();

            $table->string('organization_id', 64)->nullable()->index();

            // Parte della domanda, non un'etichetta: il PDP filtra i grant per
            // application_key, quindi una sonda che lo omette sta facendo una
            // domanda diversa da quella che l'applicazione fa davvero.
            $table->string('application_key', 191)->nullable();

            $table->string('subject_type', 32);
            $table->string('subject_id', 128);
            $table->string('permission', 191);
            $table->string('resource_ref', 191)->nullable();
            $table->json('context')->nullable();
            $table->string('current_aal', 8)->default('aal1');

            // L'esito ATTESO. Null = la sonda descrive solo un caso da osservare
            // (blast radius) senza affermare cosa debba succedere; valorizzato =
            // è anche un test di regressione, e una divergenza fallisce la CI.
            $table->boolean('expected_allowed')->nullable();

            // manual | recorded — una sonda scritta da un umano ("il CFO deve poter
            // leggere payroll") non ha lo stesso peso di una campionata dal
            // traffico, e il corpus va letto sapendo quale è quale.
            $table->string('source', 16)->default('manual');
            $table->string('label')->nullable();

            // Digest canonico della tupla: è la chiave di dedup del recorder, che
            // altrimenti riscriverebbe la stessa sonda a ogni richiesta.
            $table->string('probe_hash', 80)->unique();

            $table->timestamp('last_seen_at')->nullable();
            $table->timestamps();

            $table->index(['organization_id', 'expected_allowed'], 'iam_policy_probes_regression_idx');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('iam_policy_probes');
    }
};
