<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Auto-rotation (doc 13 §4.2). Per-client opt-in: the scheduler rotates the secret every
     * `rotate_interval_days`, and — since no human receives the new secret — stores it ENCRYPTED (reversible,
     * app-key) in `secret_pending_encrypted` so the consuming app can self-fetch it via the OAuth-plane
     * self-fetch endpoint during the grace window (authenticating with its still-valid current secret), then
     * hot-swap. The pending ciphertext is cleared once the grace lapses.
     */
    public function up(): void
    {
        Schema::table('iam_oauth_clients', function (Blueprint $table) {
            $table->boolean('auto_rotate')->default(false)->after('secret_rotated_at');
            $table->unsignedInteger('rotate_interval_days')->nullable()->after('auto_rotate');
            $table->text('secret_pending_encrypted')->nullable()->after('rotate_interval_days');
        });
    }

    public function down(): void
    {
        Schema::table('iam_oauth_clients', function (Blueprint $table) {
            $table->dropColumn(['auto_rotate', 'rotate_interval_days', 'secret_pending_encrypted']);
        });
    }
};
