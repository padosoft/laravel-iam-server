<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Padosoft\Iam\Contracts\Crypto\SecretCipher;
use Padosoft\Iam\Domain\Crypto\Models\DataKey;

uses(RefreshDatabase::class);

function cipher(): SecretCipher
{
    return app(SecretCipher::class);
}

it('round-trip senza scope (DEK per-valore)', function () {
    $v = cipher()->encrypt('segreto-123');

    expect($v['ciphertext'])->toBeString()->not->toBe('segreto-123')
        ->and($v['scope'])->toBeNull()
        ->and($v['wrapped_dek'])->toBeString()
        ->and(cipher()->decrypt($v))->toBe('segreto-123');
});

it('round-trip con scope (DEK per-scope persistita in iam_data_keys)', function () {
    $v = cipher()->encrypt('pii-mario', 'subject:usr_1');

    expect($v['scope'])->toBe('subject:usr_1')
        ->and($v['wrapped_dek'])->toBeNull()
        ->and(cipher()->decrypt($v))->toBe('pii-mario')
        ->and(DataKey::query()->where('scope', 'subject:usr_1')->count())->toBe(1);
});

it('CRYPTO-SHREDDING: dopo shred(scope) il dato è irrecuperabile (GDPR)', function () {
    $v = cipher()->encrypt('pii-da-cancellare', 'subject:usr_1');
    expect(cipher()->decrypt($v))->toBe('pii-da-cancellare');

    cipher()->shred('subject:usr_1');

    expect(fn () => cipher()->decrypt($v))->toThrow(RuntimeException::class);

    $row = DataKey::query()->where('scope', 'subject:usr_1')->first();
    expect($row->shredded_at)->not->toBeNull()
        ->and($row->wrapped_dek)->toBeNull();
});

it('scope diversi sono isolati: shred di uno non impatta l\'altro', function () {
    $a = cipher()->encrypt('x', 'tenant:a');
    $b = cipher()->encrypt('x', 'tenant:b');

    cipher()->shred('tenant:a');

    expect(fn () => cipher()->decrypt($a))->toThrow(RuntimeException::class)
        ->and(cipher()->decrypt($b))->toBe('x');
});

it('rileva la manomissione del ciphertext/MAC (authenticated encryption)', function () {
    $v = cipher()->encrypt('integro');
    $raw = (string) base64_decode($v['ciphertext'], true);
    $i = SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + 1; // byte dentro il box (non il nonce)
    $raw[$i] = $raw[$i] === "\x00" ? "\x01" : "\x00";
    $v['ciphertext'] = base64_encode($raw);

    expect(fn () => cipher()->decrypt($v))->toThrow(RuntimeException::class);
});

it('rifiuta una wrapped_dek manomessa nel path senza scope', function () {
    $v = cipher()->encrypt('x');
    $v['wrapped_dek'] = base64_encode('wrapped-dek-non-valida');

    expect(fn () => cipher()->decrypt($v))->toThrow(RuntimeException::class);
});

it('shred() su scope inesistente è un no-op sicuro', function () {
    cipher()->shred('scope:mai-esistito');

    expect(DataKey::query()->count())->toBe(0);
});

it('shred() è idempotente: il secondo non sovrascrive shredded_at', function () {
    cipher()->encrypt('x', 'tenant:a');
    cipher()->shred('tenant:a');
    $first = DataKey::query()->where('scope', 'tenant:a')->firstOrFail()->shredded_at;

    cipher()->shred('tenant:a');
    $second = DataKey::query()->where('scope', 'tenant:a')->firstOrFail()->shredded_at;

    expect($second?->equalTo($first))->toBeTrue();
});

it('non si può ri-cifrare in uno scope già shredded (fail-closed)', function () {
    cipher()->encrypt('x', 'tenant:a');
    cipher()->shred('tenant:a');

    expect(fn () => cipher()->encrypt('y', 'tenant:a'))->toThrow(RuntimeException::class);
});

it('due cifrature dello stesso testo producono ciphertext diversi (nonce/DEK)', function () {
    expect(cipher()->encrypt('x')['ciphertext'])
        ->not->toBe(cipher()->encrypt('x')['ciphertext']);
});
