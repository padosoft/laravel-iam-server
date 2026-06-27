<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/*
 * M7 — Audit tamper-evident (doc 12). Ogni evento è concatenato crittograficamente al precedente
 * nello stesso stream (hash-chain): hash(N) = SHA-256(canonical_json(evt_N) || prev_hash). Una
 * modifica/cancellazione/riordino spezza la catena in modo RILEVABILE. `iam_audit_heads` tiene la
 * testa per stream (scrittura serializzata via lock); `seq` per-stream rende un buco già sospetto.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('iam_audit_events', function (Blueprint $t): void {
            $t->ulid('uuid')->primary();                  // ULID: ordinabile temporalmente
            $t->string('stream')->index();                // es. organization_id o 'global'
            $t->unsignedBigInteger('seq');                // progressivo per stream (gap = sospetto)
            $t->timestamp('occurred_at');

            $t->string('actor_user_id')->nullable();
            $t->string('actor_client_id')->nullable();
            $t->string('actor_agent_id')->nullable();
            $t->string('actor_assurance')->nullable();    // aal raggiunto, step-up sì/no

            $t->string('target_type')->nullable();
            $t->string('target_id')->nullable();
            $t->string('organization_id')->nullable();
            $t->string('application_id')->nullable();

            $t->string('event_type');                     // grant.assigned, policy.approved, ...
            $t->string('risk_level')->default('low');
            $t->string('ip_hash')->nullable();
            $t->string('user_agent_hash')->nullable();
            $t->string('correlation_id')->nullable();

            $t->json('before_json')->nullable();
            $t->json('after_json')->nullable();
            $t->json('pii_encrypted')->nullable();         // envelope SecretCipher della PII (per-soggetto)
            $t->string('pii_dek_id')->nullable();          // scope della DEK PII (crypto-shredding GDPR)
            $t->json('metadata_json')->nullable();

            // hash-chain
            $t->char('prev_hash', 64);
            $t->char('hash', 64);
            $t->timestamp('sealed_at')->nullable();

            $t->timestamps();

            $t->unique(['stream', 'seq']);
            $t->index(['stream', 'occurred_at']);
        });

        Schema::create('iam_audit_heads', function (Blueprint $t): void {
            $t->string('stream')->primary();
            $t->char('hash', 64)->nullable();
            $t->unsignedBigInteger('seq')->default(0);
            $t->timestamp('sealed_at')->nullable();
        });

        // Checkpoint firmati (doc 12 §2.2): a intervalli si firma hash(testa) con la chiave IAM.
        // La firma (JWT ES256 sul JWKS) impedisce a un attaccante con accesso DB di RICOSTRUIRE
        // l'intera catena da zero: non può forgiare la firma senza la chiave privata.
        Schema::create('iam_audit_checkpoints', function (Blueprint $t): void {
            $t->ulid('id')->primary();
            $t->string('stream')->index();
            $t->unsignedBigInteger('up_to_seq');
            $t->char('head_hash', 64);
            $t->text('signature');                 // JWT firmato (claims: stream/seq/head_hash)
            $t->timestamp('signed_at');
            $t->timestamp('anchored_at')->nullable(); // push su store esterno/SIEM (v2)
        });

        // Outbox transazionale (doc 12 §5): l'evento di dominio si scrive nella STESSA transazione
        // del dato; un worker lo sigilla nella hash-chain e lo consegna (at-least-once). Lo status
        // protegge da doppia consegna; `audit_uuid` lega il messaggio all'evento sigillato.
        Schema::create('iam_outbox', function (Blueprint $t): void {
            $t->ulid('id')->primary();
            $t->string('event_type');
            $t->string('stream')->index();
            $t->json('payload_json');
            $t->string('status')->default('pending')->index(); // pending | delivered | failed
            $t->unsignedInteger('attempts')->default(0);
            $t->text('last_error')->nullable();                // motivo dell'ultimo fallimento (ops)
            $t->string('audit_uuid')->nullable();              // uuid dell'evento sigillato
            $t->timestamp('created_at');
            $t->timestamp('delivered_at')->nullable();
        });

        // Webhooks (doc 12 §6): subscription per-org con filtri sugli event_type; secret cifrato
        // (envelope) per la firma HMAC. Le delivery sono loggate (audit della consegna stessa) con
        // retry/backoff e DLQ (status=failed) dopo la soglia.
        Schema::create('iam_webhook_subscriptions', function (Blueprint $t): void {
            $t->ulid('id')->primary();
            $t->string('organization_id')->nullable()->index();
            $t->string('url');
            $t->json('secret_encrypted');          // envelope SecretCipher
            $t->json('event_filters');             // es. ["grant.*","policy.approved"]
            $t->string('status')->default('active'); // active | disabled
            $t->timestamps();
        });

        Schema::create('iam_webhook_deliveries', function (Blueprint $t): void {
            $t->ulid('id')->primary();
            $t->foreignUlid('subscription_id')->constrained('iam_webhook_subscriptions')->cascadeOnDelete();
            $t->string('event_uuid')->index();
            $t->unsignedInteger('attempt')->default(0);
            $t->string('status')->default('pending'); // pending|delivered|retrying|failed
            $t->unsignedSmallInteger('response_code')->nullable();
            $t->text('response_excerpt')->nullable();
            $t->text('signature')->nullable();
            $t->timestamp('next_retry_at')->nullable()->index();
            $t->timestamp('delivered_at')->nullable();
            $t->timestamps();

            $t->unique(['subscription_id', 'event_uuid']); // idempotenza: una delivery per (sub,evento)
        });

        // Legal hold (doc 12 §7): sospende il crypto-shredding di un soggetto finché attivo
        // (es. contenzioso). Senza, l'erasure GDPR cancellerebbe prove sotto obbligo di conservazione.
        Schema::create('iam_legal_holds', function (Blueprint $t): void {
            $t->ulid('id')->primary();
            $t->string('subject')->index();
            $t->string('reason');
            $t->timestamp('placed_at');
            $t->timestamp('released_at')->nullable();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('iam_legal_holds');
        Schema::dropIfExists('iam_webhook_deliveries');
        Schema::dropIfExists('iam_webhook_subscriptions');
        Schema::dropIfExists('iam_outbox');
        Schema::dropIfExists('iam_audit_checkpoints');
        Schema::dropIfExists('iam_audit_heads');
        Schema::dropIfExists('iam_audit_events');
    }
};
