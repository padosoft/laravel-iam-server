<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * In `iam.audit.ua_mode=full` the `user_agent_hash` columns hold the CLEAR User-Agent (for forensics),
     * which routinely exceeds varchar(255). Widen to text so a full-mode login (iam_sessions) or admin
     * audit (iam_audit_events) insert can neither silently truncate nor throw. In `hash` mode the value is
     * a 64-char digest, so text is harmless there.
     */
    public function up(): void
    {
        Schema::table('iam_sessions', function (Blueprint $table) {
            $table->text('user_agent_hash')->nullable()->change();
        });
        Schema::table('iam_audit_events', function (Blueprint $table) {
            $table->text('user_agent_hash')->nullable()->change();
        });
    }

    public function down(): void
    {
        Schema::table('iam_sessions', function (Blueprint $table) {
            $table->string('user_agent_hash')->nullable()->change();
        });
        Schema::table('iam_audit_events', function (Blueprint $table) {
            $table->string('user_agent_hash')->nullable()->change();
        });
    }
};
