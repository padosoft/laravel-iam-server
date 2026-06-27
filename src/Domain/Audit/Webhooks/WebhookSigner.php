<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Audit\Webhooks;

/**
 * Firma HMAC-SHA256 di un webhook (doc 12 §6): firma `timestamp.body` col secret della
 * subscription. Il ricevente ricalcola e rifiuta oltre la finestra anti-replay sul timestamp.
 * Header: `X-IAM-Signature: t=<ts>,v1=<sig>`.
 */
final class WebhookSigner
{
    public function signatureHeader(string $timestamp, string $body, string $secret): string
    {
        return 't='.$timestamp.',v1='.$this->sign($timestamp, $body, $secret);
    }

    public function sign(string $timestamp, string $body, string $secret): string
    {
        return hash_hmac('sha256', $timestamp.'.'.$body, $secret);
    }
}
