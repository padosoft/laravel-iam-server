<?php

declare(strict_types=1);

use Padosoft\Iam\Domain\Audit\Webhooks\WebhookUrlGuard;

/**
 * Risolutore deterministico per i test (niente DNS reale): l'host pubblico mappa a un IP pubblico,
 * l'host "rebinding" a un IP interno (per verificare che la validazione post-risoluzione lo blocchi).
 *
 * @param  list<string>  $ips
 */
function guardWith(array $map = ['hooks.example.com' => ['93.184.216.34']]): WebhookUrlGuard
{
    return new WebhookUrlGuard(fn (string $host): array => $map[$host] ?? []);
}

it('classifica gli URL webhook (anti SSRF)', function (string $url, bool $safe) {
    expect(guardWith()->isSafe($url))->toBe($safe);
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
    'host non risolvibile' => ['https://nope.invalid/in', false],
]);

it('ammette http verso host pubblico solo se webhook_allow_insecure è attivo (dev)', function () {
    config()->set('iam.audit.webhook_allow_insecure', true);

    expect(guardWith()->isSafe('http://hooks.example.com/in'))->toBeTrue()
        ->and(guardWith()->isSafe('http://127.0.0.1/in'))->toBeFalse();
});

it('blocca un hostname che RISOLVE a un IP interno (DNS rebinding, IAM-15)', function () {
    $guard = guardWith(['evil.example.com' => ['169.254.169.254']]);

    expect($guard->isSafe('https://evil.example.com/steal'))->toBeFalse()
        ->and($guard->safeResolveTarget('https://evil.example.com/steal'))->toBeNull();
});

it('ritorna un target pinnabile (host/port/ip) per un host pubblico', function () {
    $target = guardWith()->safeResolveTarget('https://hooks.example.com/in');

    expect($target)->toMatchArray([
        'host' => 'hooks.example.com',
        'port' => 443,
        'ip' => '93.184.216.34',
    ]);
});
