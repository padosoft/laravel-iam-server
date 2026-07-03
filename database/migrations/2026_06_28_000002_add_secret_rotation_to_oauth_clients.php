<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Client-secret lifecycle (doc 13 §4.1): scheduled expiry + zero-downtime rotation with a grace
     * window. On rotation the current secret moves to `secret_previous` (valid until
     * `secret_previous_expires_at`) while a fresh `secret` is issued (expiring at `secret_expires_at`).
     * validateClient accepts either during grace, so a consuming app can roll over without downtime.
     */
    public function up(): void
    {
        Schema::table('iam_oauth_clients', function (Blueprint $table) {
            $table->timestamp('secret_expires_at')->nullable()->after('secret');
            $table->string('secret_previous')->nullable()->after('secret_expires_at');
            $table->timestamp('secret_previous_expires_at')->nullable()->after('secret_previous');
            $table->timestamp('secret_rotated_at')->nullable()->after('secret_previous_expires_at');
        });
    }

    public function down(): void
    {
        Schema::table('iam_oauth_clients', function (Blueprint $table) {
            $table->dropColumn(['secret_expires_at', 'secret_previous', 'secret_previous_expires_at', 'secret_rotated_at']);
        });
    }
};
