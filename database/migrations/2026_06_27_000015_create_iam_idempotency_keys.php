<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/*
 * M10.1 — Idempotency-Key per le mutazioni dell'Admin API (doc 16 §6). Una chiave per (attore, key)
 * memorizza l'esito della prima richiesta: un retry con la stessa chiave NON riesegue l'azione ma
 * rigioca la risposta salvata (at-most-once lato effetti). `request_hash` lega la chiave al payload:
 * stessa chiave + payload diverso = errore client (no riuso accidentale di una chiave per altro).
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('iam_idempotency_keys', function (Blueprint $t): void {
            $t->ulid('id')->primary();
            $t->string('actor_ref');                 // type:id dell'attore (isola le chiavi per attore)
            $t->string('idempotency_key');
            $t->string('method', 10);
            $t->string('path');
            $t->string('request_hash', 64);          // sha256 di method+path+body
            $t->unsignedSmallInteger('response_status')->nullable();
            $t->longText('response_body')->nullable();
            $t->timestamps();

            $t->unique(['actor_ref', 'idempotency_key']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('iam_idempotency_keys');
    }
};
