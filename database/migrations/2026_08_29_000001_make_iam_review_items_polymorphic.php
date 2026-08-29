<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/*
 * IGA — un item di access review non certifica più soltanto un grant RBAC/ABAC.
 *
 * `grant_id` diventa la coppia polimorfica (`reviewable_type`, `reviewable_id`), così un modulo
 * opzionale può registrare la propria sorgente certificabile (prima fra tutte: le delegation grant
 * di `laravel-iam-agents`) senza che il core la conosca. Le righe esistenti diventano
 * `reviewable_type = 'grant'` — l'inventario storico resta esattamente quello che era.
 *
 * Il vecchio `unique(campaign_id, grant_id)` diventa `unique(campaign_id, reviewable_type,
 * reviewable_id)`: un accesso compare una sola volta per campagna, ma due sorgenti possono avere id
 * omonimi senza collidere.
 *
 * La FK verso `iam_grants` sparisce con la colonna: una colonna polimorfica non può averne una. In
 * pratica non si perde nulla di sostanziale — i grant si revocano (`revoked_at`), non si cancellano,
 * e l'evidenza d'audit di una review NON deve sparire insieme al suo oggetto.
 *
 * SQLite non sa rimuovere una colonna citata in una definizione di foreign key (l'ALTER passa, ma
 * l'integrity-check successivo fallisce), quindi lì la tabella si ricostruisce e si ricopia. Sugli
 * altri driver basta sganciare la FK.
 */
return new class extends Migration
{
    public function up(): void
    {
        if (DB::connection()->getDriverName() === 'sqlite') {
            $this->rebuildForSqlite();

            return;
        }

        Schema::table('iam_review_items', function (Blueprint $t): void {
            $t->string('reviewable_type')->nullable()->after('campaign_id');
            $t->string('reviewable_id')->nullable()->after('reviewable_type');
        });

        $this->backfill();

        Schema::table('iam_review_items', function (Blueprint $t): void {
            $t->dropUnique(['campaign_id', 'grant_id']);
            $t->dropForeign(['grant_id']);
            $t->dropColumn('grant_id');
        });

        Schema::table('iam_review_items', function (Blueprint $t): void {
            $t->string('reviewable_type')->nullable(false)->change();
            $t->string('reviewable_id')->nullable(false)->change();
            $t->unique(['campaign_id', 'reviewable_type', 'reviewable_id'], 'iam_review_items_reviewable_unique');
            $t->index(['reviewable_type', 'reviewable_id'], 'iam_review_items_reviewable_index');
        });
    }

    public function down(): void
    {
        // Solo gli item che certificavano un grant hanno una casa nello schema precedente; gli altri
        // (delegation grant, ecc.) verrebbero orfani di una FK che non regge, quindi il rollback li
        // rimuove. Un down() che inventa righe è peggio di uno che dichiara cosa perde.
        DB::table('iam_review_items')->where('reviewable_type', '!=', 'grant')->delete();

        if (DB::connection()->getDriverName() === 'sqlite') {
            $this->restoreForSqlite();

            return;
        }

        Schema::table('iam_review_items', function (Blueprint $t): void {
            $t->dropUnique('iam_review_items_reviewable_unique');
            $t->dropIndex('iam_review_items_reviewable_index');
            $t->foreignUlid('grant_id')->nullable()->after('campaign_id')->constrained('iam_grants')->cascadeOnDelete();
        });

        DB::table('iam_review_items')->update(['grant_id' => DB::raw($this->quote('reviewable_id'))]);

        Schema::table('iam_review_items', function (Blueprint $t): void {
            $t->dropColumn(['reviewable_type', 'reviewable_id']);
            $t->unique(['campaign_id', 'grant_id']);
        });
    }

    /** Ricostruzione completa: SQLite non rimuove una colonna citata da una FK. */
    private function rebuildForSqlite(): void
    {
        Schema::create('iam_review_items_new', function (Blueprint $t): void {
            $t->ulid('id')->primary();
            $t->foreignUlid('campaign_id')->constrained('iam_review_campaigns')->cascadeOnDelete();
            $t->string('reviewable_type');
            $t->string('reviewable_id');
            $t->string('reviewer_subject')->nullable();
            $t->string('decision')->default('pending');
            $t->json('signals_json')->nullable();
            $t->timestamp('decided_at')->nullable();
            $t->string('decided_by')->nullable();
            $t->text('note')->nullable();
            $t->timestamps();

            $t->unique(['campaign_id', 'reviewable_type', 'reviewable_id'], 'iam_review_items_reviewable_unique');
            $t->index(['campaign_id', 'decision']);
            $t->index(['reviewable_type', 'reviewable_id'], 'iam_review_items_reviewable_index');
        });

        DB::statement(
            'insert into iam_review_items_new '.
            '(id, campaign_id, reviewable_type, reviewable_id, reviewer_subject, decision, signals_json, decided_at, decided_by, note, created_at, updated_at) '.
            "select id, campaign_id, 'grant', grant_id, reviewer_subject, decision, signals_json, decided_at, decided_by, note, created_at, updated_at ".
            'from iam_review_items'
        );

        Schema::drop('iam_review_items');
        Schema::rename('iam_review_items_new', 'iam_review_items');
    }

    private function restoreForSqlite(): void
    {
        Schema::create('iam_review_items_old', function (Blueprint $t): void {
            $t->ulid('id')->primary();
            $t->foreignUlid('campaign_id')->constrained('iam_review_campaigns')->cascadeOnDelete();
            $t->foreignUlid('grant_id')->constrained('iam_grants')->cascadeOnDelete();
            $t->string('reviewer_subject')->nullable();
            $t->string('decision')->default('pending');
            $t->json('signals_json')->nullable();
            $t->timestamp('decided_at')->nullable();
            $t->string('decided_by')->nullable();
            $t->text('note')->nullable();
            $t->timestamps();

            $t->unique(['campaign_id', 'grant_id']);
            $t->index(['campaign_id', 'decision']);
        });

        DB::statement(
            'insert into iam_review_items_old '.
            '(id, campaign_id, grant_id, reviewer_subject, decision, signals_json, decided_at, decided_by, note, created_at, updated_at) '.
            'select id, campaign_id, reviewable_id, reviewer_subject, decision, signals_json, decided_at, decided_by, note, created_at, updated_at '.
            'from iam_review_items'
        );

        Schema::drop('iam_review_items');
        Schema::rename('iam_review_items_old', 'iam_review_items');
    }

    private function backfill(): void
    {
        DB::table('iam_review_items')->update([
            'reviewable_type' => 'grant',
            'reviewable_id' => DB::raw($this->quote('grant_id')),
        ]);
    }

    /** Quota un identificatore di colonna per il grammar del driver corrente. */
    private function quote(string $column): string
    {
        return DB::connection()->getQueryGrammar()->wrap($column);
    }
};
