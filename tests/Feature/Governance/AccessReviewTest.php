<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Padosoft\Iam\Domain\Audit\Models\AuditEvent;
use Padosoft\Iam\Domain\Authorization\Models\Grant;
use Padosoft\Iam\Domain\Governance\Reviews\CampaignEngine;
use Padosoft\Iam\Domain\Governance\Reviews\Models\ReviewCampaign;
use Padosoft\Iam\Domain\Governance\Reviews\Models\ReviewItem;
use Padosoft\Iam\Domain\Organizations\Models\Organization;

uses(RefreshDatabase::class);

function reviewGrant(array $overrides = []): Grant
{
    return Grant::create(array_merge([
        'subject_type' => 'user', 'subject_id' => 'usr_x',
        'privilege_type' => 'permission', 'privilege_key' => 'warehouse:stock.read',
        'application_key' => 'warehouse',
    ], $overrides));
}

function campaign(array $overrides = []): ReviewCampaign
{
    return ReviewCampaign::create(array_merge([
        'name' => 'Q1 Review', 'on_unconfirmed' => 'revoke',
    ], $overrides));
}

it('open genera un item con segnali smart per ogni grant attivo nello scope', function () {
    $g1 = reviewGrant(['subject_id' => 'usr_a']);
    $g2 = reviewGrant(['subject_id' => 'usr_b', 'is_privileged' => true]);
    reviewGrant(['subject_id' => 'usr_c', 'application_key' => 'billing']); // fuori scope

    $c = campaign(['scope_json' => ['application_keys' => ['warehouse']]]);
    $created = app(CampaignEngine::class)->open($c);

    expect($created)->toBe(2)
        ->and($c->fresh()->status)->toBe('running')
        ->and(ReviewItem::query()->where('campaign_id', $c->id)->count())->toBe(2);

    $item = ReviewItem::query()->where('grant_id', $g2->id)->first();
    expect($item->signals_json['never_used'])->toBeTrue()
        ->and($item->signals_json['privileged'])->toBeTrue();
});

it('open è idempotente: riaprire non duplica gli item', function () {
    reviewGrant();
    $c = campaign();

    app(CampaignEngine::class)->open($c);
    $created2 = app(CampaignEngine::class)->open($c);

    expect($created2)->toBe(0)
        ->and(ReviewItem::query()->where('campaign_id', $c->id)->count())->toBe(1);
});

it('un reviewer che revoca rimuove il grant e audita la mutazione', function () {
    $grant = reviewGrant();
    $c = campaign();
    app(CampaignEngine::class)->open($c);
    $item = ReviewItem::query()->where('grant_id', $grant->id)->firstOrFail();

    app(CampaignEngine::class)->decide($item, 'revoked', 'user:mgr', 'non serve più');

    expect($grant->fresh()->revoked_at)->not->toBeNull()
        ->and($item->fresh()->decision)->toBe('revoked')
        ->and(AuditEvent::query()->where('event_type', 'iam.grant.revoked')->where('target_id', $grant->id)->exists())->toBeTrue();
});

it('approve conferma l\'accesso senza toccare il grant', function () {
    $grant = reviewGrant();
    $c = campaign();
    app(CampaignEngine::class)->open($c);
    $item = ReviewItem::query()->where('grant_id', $grant->id)->firstOrFail();

    app(CampaignEngine::class)->decide($item, 'approved', 'user:mgr');

    expect($grant->fresh()->revoked_at)->toBeNull()
        ->and($item->fresh()->decision)->toBe('approved');
});

it('close applica on_unconfirmed=revoke ai soli item pending (auto-revoca)', function () {
    $kept = reviewGrant(['subject_id' => 'usr_keep']);
    $unconfirmed = reviewGrant(['subject_id' => 'usr_drop']);
    $c = campaign(['on_unconfirmed' => 'revoke']);
    $engine = app(CampaignEngine::class);
    $engine->open($c);

    // Un reviewer conferma esplicitamente il primo; il secondo resta pending.
    $keptItem = ReviewItem::query()->where('grant_id', $kept->id)->firstOrFail();
    $engine->decide($keptItem, 'approved', 'user:mgr');

    $processed = $engine->close($c);

    expect($processed)->toBe(1)
        ->and($kept->fresh()->revoked_at)->toBeNull()      // confermato → resta
        ->and($unconfirmed->fresh()->revoked_at)->not->toBeNull() // non confermato → revocato
        ->and($c->fresh()->status)->toBe('completed');
});

it('close con on_unconfirmed=keep conferma i pending senza revocare', function () {
    $grant = reviewGrant();
    $c = campaign(['on_unconfirmed' => 'keep']);
    $engine = app(CampaignEngine::class);
    $engine->open($c);

    $engine->close($c);

    $item = ReviewItem::query()->where('grant_id', $grant->id)->firstOrFail();
    expect($grant->fresh()->revoked_at)->toBeNull()
        ->and($item->decision)->toBe('approved');
});

it('decision/decided_by NON sono fillable (storia immutabile)', function () {
    $grant = reviewGrant();
    $c = campaign();
    app(CampaignEngine::class)->open($c);

    // Tentativo di forzare una decisione via mass-assignment: deve essere ignorato.
    $item = ReviewItem::query()->where('grant_id', $grant->id)->firstOrFail();
    $item->fill(['decision' => 'approved', 'decided_by' => 'attacker'])->save();

    expect($item->fresh()->decision)->toBe('pending')
        ->and($item->fresh()->decided_by)->toBeNull();
});

it('remind elenca i reviewer distinti con item pending', function () {
    reviewGrant(['subject_id' => 'usr_a']);
    reviewGrant(['subject_id' => 'usr_b']);
    $c = campaign(['reviewer_strategy' => 'named', 'scope_json' => ['reviewer' => 'user:owner']]);
    $engine = app(CampaignEngine::class);
    $engine->open($c);

    expect($engine->remind($c))->toBe(['user:owner']);
});

it('il comando iam:reviews:open apre la campagna', function () {
    reviewGrant();
    $c = campaign();

    $this->artisan('iam:reviews:open', ['--campaign' => $c->id])
        ->assertSuccessful();

    expect($c->fresh()->status)->toBe('running');
});

it('decide su un item già deciso lancia (no last-write-wins)', function () {
    $grant = reviewGrant();
    $c = campaign();
    app(CampaignEngine::class)->open($c);
    $item = ReviewItem::query()->where('grant_id', $grant->id)->firstOrFail();

    app(CampaignEngine::class)->decide($item, 'approved', 'user:mgr');

    expect(fn () => app(CampaignEngine::class)->decide($item, 'revoked', 'user:other'))
        ->toThrow(RuntimeException::class);
});

it('close su una campagna non running (draft/completed) è rifiutato', function () {
    $c = campaign(); // draft, mai aperta
    expect(fn () => app(CampaignEngine::class)->close($c))->toThrow(RuntimeException::class);

    app(CampaignEngine::class)->open($c);
    app(CampaignEngine::class)->close($c); // ok: running → completed
    expect(fn () => app(CampaignEngine::class)->close($c->fresh()))->toThrow(RuntimeException::class);
});

it('open non sposta opened_at sulla riapertura', function () {
    reviewGrant(['subject_id' => 'usr_a']);
    $c = campaign();
    $engine = app(CampaignEngine::class);
    $engine->open($c);
    $firstOpenedAt = $c->fresh()->opened_at;

    reviewGrant(['subject_id' => 'usr_b']);
    $engine->open($c->fresh());

    expect($c->fresh()->opened_at->equalTo($firstOpenedAt))->toBeTrue()
        ->and(ReviewItem::query()->where('campaign_id', $c->id)->count())->toBe(2);
});

it('una campagna di tenant NON certifica i grant globali (isolamento cross-tenant)', function () {
    $org = Organization::create(['key' => 'acme', 'name' => 'Acme']);
    $tenantGrant = reviewGrant(['subject_id' => 'usr_t', 'organization_id' => $org->id]);
    $globalGrant = reviewGrant(['subject_id' => 'usr_g', 'organization_id' => null]);

    $c = campaign(['organization_id' => $org->id, 'on_unconfirmed' => 'revoke']);
    $engine = app(CampaignEngine::class);
    $engine->open($c);
    $engine->close($c);

    expect($tenantGrant->fresh()->revoked_at)->not->toBeNull()  // grant del tenant: certificato/revocato
        ->and($globalGrant->fresh()->revoked_at)->toBeNull()    // grant globale: intoccato
        ->and(ReviewItem::query()->where('campaign_id', $c->id)->count())->toBe(1);
});

it('signals_json è uno snapshot immutabile (non mass-assignable dopo la creazione)', function () {
    $grant = reviewGrant();
    $c = campaign();
    app(CampaignEngine::class)->open($c);
    $item = ReviewItem::query()->where('grant_id', $grant->id)->firstOrFail();

    $item->fill(['signals_json' => ['tampered' => true]])->save();

    expect($item->fresh()->signals_json)->not->toHaveKey('tampered');
});

it('il comando iam:reviews:close auto-revoca i non confermati', function () {
    $grant = reviewGrant();
    $c = campaign(['on_unconfirmed' => 'revoke']);
    app(CampaignEngine::class)->open($c);

    $this->artisan('iam:reviews:close', ['--campaign' => $c->id])
        ->assertSuccessful();

    expect($grant->fresh()->revoked_at)->not->toBeNull()
        ->and($c->fresh()->status)->toBe('completed');
});
