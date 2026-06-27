<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Audit\Webhooks;

use Illuminate\Support\Facades\Http;
use Padosoft\Iam\Contracts\Crypto\SecretCipher;
use Padosoft\Iam\Domain\Audit\Models\AuditEvent;
use Padosoft\Iam\Domain\Audit\Webhooks\Models\WebhookDelivery;
use Padosoft\Iam\Domain\Audit\Webhooks\Models\WebhookSubscription;

/**
 * Esegue un singolo tentativo di consegna webhook e aggiorna il log (doc 12 §6). Firma HMAC sul
 * body, header anti-replay/idempotency, esito su 2xx → delivered; altrimenti retry con backoff
 * esponenziale + jitter; oltre la soglia → failed (DLQ). Condiviso da dispatcher e retrier.
 */
final class WebhookSender
{
    public function __construct(
        private readonly SecretCipher $cipher,
        private readonly WebhookSigner $signer,
        private readonly WebhookUrlGuard $urlGuard,
    ) {}

    public function send(WebhookSubscription $subscription, WebhookDelivery $delivery, AuditEvent $event): void
    {
        // Claim atomico (anti TOCTOU): solo un worker passa da pending/retrying a 'sending'. Chi
        // perde il claim (o trova la riga già delivered/failed) esce senza inviare di nuovo.
        $claimed = WebhookDelivery::query()
            ->whereKey($delivery->getKey())
            ->whereIn('status', ['pending', 'retrying'])
            ->update(['status' => 'sending']);
        if ($claimed !== 1) {
            return;
        }

        // SSRF: un URL non sicuro non diventerà sicuro ritentando → DLQ immediata (no retry).
        if (!$this->urlGuard->isSafe($subscription->url)) {
            $delivery->forceFill([
                'attempt' => $delivery->attempt + 1,
                'status' => 'failed',
                'response_excerpt' => 'destinazione bloccata: URL non sicuro (SSRF/scheme)',
                'next_retry_at' => null,
            ])->save();

            return;
        }

        $attempt = $delivery->attempt + 1;
        $signatureHeader = null;

        // Tutto il corpo post-claim è nel try: se json_encode/decrypt/HTTP lanciano, la riga NON
        // resta bloccata in 'sending' (che il retrier non recupererebbe) ma torna retrying/failed.
        try {
            $body = json_encode($this->payload($event), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
            $timestamp = (string) now()->getTimestamp();
            $secret = $this->cipher->decrypt($subscription->secret_encrypted);
            $signatureHeader = $this->signer->signatureHeader($timestamp, $body, $secret);

            $response = Http::withHeaders([
                'Content-Type' => 'application/json',
                'X-IAM-Signature' => $signatureHeader,
                'X-IAM-Timestamp' => $timestamp,
                'X-IAM-Event-Id' => $event->uuid, // idempotency key per il ricevente
            ])->withBody($body, 'application/json')->post($subscription->url);

            if ($response->successful()) {
                $delivery->forceFill([
                    'attempt' => $attempt,
                    'status' => 'delivered',
                    'response_code' => $response->status(),
                    'response_excerpt' => mb_substr($response->body(), 0, 500),
                    'signature' => $signatureHeader,
                    'delivered_at' => now(),
                    'next_retry_at' => null,
                ])->save();

                return;
            }

            $this->fail($delivery, $attempt, $response->status(), mb_substr($response->body(), 0, 500), $signatureHeader);
        } catch (\Throwable $e) {
            // Errore di trasporto/serializzazione/decrypt: fallimento ritentabile (mai 'sending' orfano).
            $this->fail($delivery, $attempt, null, mb_substr($e->getMessage(), 0, 500), $signatureHeader);
        }
    }

    private function fail(WebhookDelivery $delivery, int $attempt, ?int $code, string $excerpt, ?string $signatureHeader): void
    {
        $exhausted = $attempt >= $this->maxAttempts();

        $delivery->forceFill([
            'attempt' => $attempt,
            'status' => $exhausted ? 'failed' : 'retrying',
            'response_code' => $code,
            'response_excerpt' => $excerpt,
            'signature' => $signatureHeader,
            'next_retry_at' => $exhausted ? null : now()->addSeconds($this->backoffSeconds($attempt)),
        ])->save();
    }

    /** Backoff esponenziale con jitter: base * 2^(attempt-1) + [0..base) secondi. */
    private function backoffSeconds(int $attempt): int
    {
        $base = $this->config('iam.audit.webhook_backoff_base', 10);
        $exp = $base * (2 ** max(0, $attempt - 1));

        return $exp + random_int(0, max(0, $base - 1)); // jitter in [0..base)
    }

    private function maxAttempts(): int
    {
        return $this->config('iam.audit.webhook_max_attempts', 5);
    }

    private function config(string $key, int $default): int
    {
        $value = config($key, $default);

        return is_int($value) && $value > 0 ? $value : $default;
    }

    /**
     * @return array<string, mixed>
     */
    private function payload(AuditEvent $event): array
    {
        return [
            'id' => $event->uuid,
            'type' => $event->event_type,
            'time' => $event->occurred_at->utc()->format('Y-m-d\TH:i:s\Z'),
            'stream' => $event->stream,
            'organization_id' => $event->organization_id,
            'data' => [
                'target_type' => $event->target_type,
                'target_id' => $event->target_id,
                'risk_level' => $event->risk_level,
                'before' => $event->before_json,
                'after' => $event->after_json,
            ],
        ];
    }
}
