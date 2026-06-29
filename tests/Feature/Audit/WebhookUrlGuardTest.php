<?php

declare(strict_types=1);

use Padosoft\Iam\Domain\Audit\Webhooks\WebhookUrlGuard;

it('classifica gli URL webhook (anti SSRF)', function (string $url, bool $safe) {
    expect(app(WebhookUrlGuard::class)->isSafe($url))->toBe($safe);
})->with([
    'https pubblico' => ['https://hooks.example.com/in', true],
    'http non sicuro' => ['http://hooks.example.com/in', false],
    'metadata link-local' => ['https://169.254.169.254/latest', false],
    'loopback v4' => ['https://127.0.0.1/in', false],
    'privato 192.168' => ['https://192.168.1.10/in', false],
    'privato 10.x' => ['https://10.0.0.5/in', false],
    'loopback v6' => ['https://[::1]/in', false],
    'scheme file' => ['file:///etc/passwd', false],
    'scheme javascript' => ['javascript:alert(1)', false],
    'host mancante' => ['https:///in', false],
    'IP decimale (127.0.0.1)' => ['https://2130706433/in', false],
    'IP shorthand 127.1' => ['https://127.1/in', false],
    'IP esadecimale' => ['https://0x7f.1/in', false],
]);

it('ammette http verso host pubblico solo se webhook_allow_insecure è attivo (dev)', function () {
    config()->set('iam.audit.webhook_allow_insecure', true);

    expect(app(WebhookUrlGuard::class)->isSafe('http://hooks.example.com/in'))->toBeTrue()
        ->and(app(WebhookUrlGuard::class)->isSafe('http://127.0.0.1/in'))->toBeFalse();
});
