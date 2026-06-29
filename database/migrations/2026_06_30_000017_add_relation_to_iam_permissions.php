<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Permission→relation binding (doc 18 §7.2): una permission può dichiarare la relazione ReBAC
 * richiesta sulla risorsa. Se valorizzata, il PDP aggiunge un permit quando il soggetto HA quella
 * relazione sulla risorsa del query. Nullable → backward-compatible (le permission RBAC restano tali).
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('iam_permissions', function (Blueprint $t): void {
            $t->string('relation')->nullable()->after('action');
        });
    }

    public function down(): void
    {
        Schema::table('iam_permissions', function (Blueprint $t): void {
            $t->dropColumn('relation');
        });
    }
};
