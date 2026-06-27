<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/*
 * M8.3 — Access Reviews / Certification (doc 14 §3). Una campaign engine genera periodicamente
 * revisioni degli accessi, le arricchisce con segnali smart (snapshot in items.signals_json) e le
 * instrada ai reviewer; a scadenza applica on_unconfirmed (revoke|keep|suspend) sui pending. Lo
 * storico (items + decisioni) è immutabile ed esportabile per gli auditor (SOX/ISO 27001/SOC2).
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('iam_review_campaigns', function (Blueprint $t): void {
            $t->ulid('id')->primary();
            $t->foreignUlid('organization_id')->nullable()->constrained('iam_organizations')->nullOnDelete();
            $t->string('name');
            $t->json('scope_json')->nullable();              // app/ruoli/criteri inclusi
            $t->string('reviewer_strategy')->default('named'); // manager|resource_owner|named
            $t->timestamp('due_at')->nullable();
            $t->string('status')->default('draft');          // draft|running|completed|expired
            $t->string('on_unconfirmed')->default('revoke'); // revoke|keep|suspend
            $t->string('created_by')->nullable();
            $t->timestamp('opened_at')->nullable();
            $t->timestamp('closed_at')->nullable();
            $t->timestamps();

            $t->index(['status', 'due_at']);
        });

        Schema::create('iam_review_items', function (Blueprint $t): void {
            $t->ulid('id')->primary();
            $t->foreignUlid('campaign_id')->constrained('iam_review_campaigns')->cascadeOnDelete();
            $t->foreignUlid('grant_id')->constrained('iam_grants')->cascadeOnDelete();
            $t->string('reviewer_subject')->nullable();      // chi deve certificare (type:id)
            $t->string('decision')->default('pending');      // pending|approved|revoked|delegated
            $t->json('signals_json')->nullable();            // snapshot dei segnali smart
            $t->timestamp('decided_at')->nullable();
            $t->string('decided_by')->nullable();
            $t->text('note')->nullable();
            $t->timestamps();

            // Un grant compare una sola volta per campagna (no doppia certificazione).
            $t->unique(['campaign_id', 'grant_id']);
            $t->index(['campaign_id', 'decision']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('iam_review_items');
        Schema::dropIfExists('iam_review_campaigns');
    }
};
