<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/*
 * M4 — Chiavi di firma JWT (EC P-256 / ES256). La chiave privata è custodita CIFRATA
 * (incartata via KeyProvider/KEK); la pubblica è esposta nel JWKS. Rotazione con overlap
 * (doc 13 §8, doc 11 §6).
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('iam_signing_keys', function (Blueprint $t): void {
            $t->ulid('id')->primary();
            $t->string('kid')->unique();
            $t->string('alg')->default('ES256');
            $t->json('public_jwk');          // JWK pubblica per il JWKS
            $t->text('public_pem');          // PEM pubblica per la verifica firma
            $t->text('private_wrapped');     // PEM privata incartata (json del wrapped)
            $t->string('status')->default('active'); // active | overlap | revoked
            $t->timestamp('rotated_at')->nullable();
            $t->timestamp('revoked_at')->nullable();
            $t->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('iam_signing_keys');
    }
};
