<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/*
 * M3 — Crypto: Data Encryption Keys per-scope (envelope encryption, doc 11 §3, §8).
 * Crypto-shredding GDPR: distruggere la DEK di uno scope (shredded_at + wrapped_dek=null)
 * rende irrecuperabili tutti i dati cifrati con essa, senza toccare i ciphertext.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('iam_data_keys', function (Blueprint $t): void {
            $t->ulid('id')->primary();
            $t->string('scope')->unique();      // es. tenant:org_x | subject:usr_y
            $t->text('wrapped_dek')->nullable(); // DEK incartata dalla KEK (null = shredded)
            $t->string('key_id');                // riferimento KEK
            $t->unsignedInteger('key_version')->default(1);
            $t->timestamp('shredded_at')->nullable();
            $t->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('iam_data_keys');
    }
};
