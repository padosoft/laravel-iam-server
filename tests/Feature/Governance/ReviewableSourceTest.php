<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Padosoft\Iam\Domain\Audit\Models\AuditEvent;
use Padosoft\Iam\Domain\Authorization\Models\Grant;
use Padosoft\Iam\Domain\Governance\Reviews\CampaignEngine;
use Padosoft\Iam\Domain\Governance\Reviews\Models\ReviewCampaign;
use Padosoft\Iam\Domain\Governance\Reviews\Models\ReviewItem;
use Padosoft\Iam\Domain\Governance\Reviews\Reviewable\GrantReviewableSource;
use Padosoft\Iam\Domain\Governance\Reviews\Reviewable\ReviewableRef;
use Padosoft\Iam\Domain\Governance\Reviews\Reviewable\ReviewableRegistry;
use Padosoft\Iam\Domain\Governance\Reviews\Reviewable\ReviewableSource;

uses(RefreshDatabase::class);

/**
 * Sorgente finta che sta per un modulo opzionale (nel mondo reale: le delegation grant di
 * laravel-iam-agents). Registra cosa le è stato chiesto di revocare, così i test possono
 * distinguere "l'engine ha marcato l'item" da "l'accesso è stato davvero tolto".
 */
final class FakeReviewableSource implements ReviewableSource
{
    /** @var list<array{id: string, by: string, reason: string, context: array<string, mixed>}> */
    public array $revoked = [];

    /** @param list<string> $ids */
    public function __construct(
        private readonly array $ids = [],
        private readonly string $type = 'fake_access',
        public bool $revokeSucceeds = true,
    ) {}

    public function type(): string
    {
        return $this->type;
    }

    public function label(): string
    {
        return 'Fake accesses';
    }

    public function scoped(ReviewCampaign $campaign): iterable
    {
        foreach ($this->ids as $id) {
            yield new ReviewableRef($this->type, $id, 'user:reviewer', ['fake' => true]);
        }
    }

    public function revoke(string $id, string $by, string $reason, array $context = []): bool
    {
        $this->revoked[] = ['id' => $id, 'by' => $by, 'reason' => $reason, 'context' => $context];

        return $this->revokeSucceeds;
    }

    public function describeMany(array $ids): array
    {
        $out = [];
        foreach ($ids as $id) {
            $out[$id] = ['fake_label' => 'access '.$id];
        }

        return $out;
    }
}

function registerFake(FakeReviewableSource $source): void
{
    app(ReviewableRegistry::class)->register($source);
}

function polyCampaign(array $overrides = []): ReviewCampaign
{
    return ReviewCampaign::create(array_merge([
        'name' => 'Delegation review', 'on_unconfirmed' => 'revoke',
    ], $overrides));
}

function polyGrant(array $overrides = []): Grant
{
    return Grant::create(array_merge([
        'subject_type' => 'user', 'subject_id' => 'usr_x',
        'privilege_type' => 'permission', 'privilege_key' => 'warehouse:stock.read',
        'application_key' => 'warehouse',
    ], $overrides));
}

it('senza reviewable_types una campagna certifica SOLO i grant (nessuna sorpresa retroattiva)', function () {
    // Installare un modulo che registra una sorgente non deve far comparire accessi inattesi
    // dentro campagne già pianificate: l'inclusione è esplicita.
    polyGrant();
    registerFake(new FakeReviewableSource(['acc_1', 'acc_2']));

    $c = polyCampaign();
    $created = app(CampaignEngine::class)->open($c);

    expect($created)->toBe(1)
        ->and(ReviewItem::query()->where('reviewable_type', 'fake_access')->count())->toBe(0);
});

it('una campagna che include una sorgente registrata ne certifica gli accessi', function () {
    polyGrant();
    registerFake(new FakeReviewableSource(['acc_1', 'acc_2']));

    $c = polyCampaign(['scope_json' => ['reviewable_types' => ['grant', 'fake_access']]]);
    $created = app(CampaignEngine::class)->open($c);

    expect($created)->toBe(3);

    $item = ReviewItem::query()->where('reviewable_type', 'fake_access')->where('reviewable_id', 'acc_1')->firstOrFail();
    expect($item->reviewer_subject)->toBe('user:reviewer')
        ->and($item->signals_json)->toBe(['fake' => true]);
});

it('una campagna può certificare SOLO la sorgente del modulo, senza i grant', function () {
    polyGrant();
    registerFake(new FakeReviewableSource(['acc_1']));

    $c = polyCampaign(['scope_json' => ['reviewable_types' => ['fake_access']]]);
    app(CampaignEngine::class)->open($c);

    expect(ReviewItem::query()->where('reviewable_type', 'grant')->count())->toBe(0)
        ->and(ReviewItem::query()->where('reviewable_type', 'fake_access')->count())->toBe(1);
});

it('open resta idempotente per (campagna, tipo, id)', function () {
    registerFake(new FakeReviewableSource(['acc_1']));
    $c = polyCampaign(['scope_json' => ['reviewable_types' => ['fake_access']]]);
    $engine = app(CampaignEngine::class);

    expect($engine->open($c))->toBe(1)
        ->and($engine->open($c))->toBe(0)
        ->and(ReviewItem::query()->count())->toBe(1);
});

it('due sorgenti con lo stesso id non collidono (l\'unicità include il tipo)', function () {
    // Un grant e un accesso del modulo possono chiamarsi uguale: la coppia (tipo, id) li distingue.
    $grant = polyGrant();
    registerFake(new FakeReviewableSource([$grant->id]));

    $c = polyCampaign(['scope_json' => ['reviewable_types' => ['grant', 'fake_access']]]);

    expect(app(CampaignEngine::class)->open($c))->toBe(2)
        ->and(ReviewItem::query()->where('reviewable_id', $grant->id)->count())->toBe(2);
});

it('la revoca del reviewer è delegata alla sorgente, col contesto della campagna', function () {
    $fake = new FakeReviewableSource(['acc_1']);
    registerFake($fake);

    $c = polyCampaign(['scope_json' => ['reviewable_types' => ['fake_access']]]);
    $engine = app(CampaignEngine::class);
    $engine->open($c);

    $item = ReviewItem::query()->firstOrFail();
    $engine->decide($item, 'revoked', 'user:admin', 'non serve più');

    expect($fake->revoked)->toHaveCount(1)
        ->and($fake->revoked[0]['id'])->toBe('acc_1')
        ->and($fake->revoked[0]['by'])->toBe('user:admin')
        ->and($fake->revoked[0]['context']['campaign_id'])->toBe($c->id)
        ->and($fake->revoked[0]['context']['review_item_id'])->toBe($item->id)
        ->and($item->fresh()->decision)->toBe('revoked');
});

it('close applica on_unconfirmed anche agli accessi del modulo', function () {
    $fake = new FakeReviewableSource(['acc_1']);
    registerFake($fake);

    $c = polyCampaign(['scope_json' => ['reviewable_types' => ['fake_access']]]);
    $engine = app(CampaignEngine::class);
    $engine->open($c);

    expect($engine->close($c))->toBe(1)
        ->and($fake->revoked)->toHaveCount(1)
        ->and(ReviewItem::query()->firstOrFail()->decision)->toBe('revoked');
});

it('un item la cui sorgente non è più registrata NON viene marcato revocato', function () {
    // Il caso che conta: il modulo è stato disinstallato. Marcare l'item `revoked` senza aver
    // revocato nulla scriverebbe nell'evidenza d'audit una revoca mai avvenuta.
    registerFake(new FakeReviewableSource(['acc_1']));
    $c = polyCampaign(['scope_json' => ['reviewable_types' => ['fake_access']]]);
    $engine = app(CampaignEngine::class);
    $engine->open($c);

    // Simula la disinstallazione: registro ricostruito senza la sorgente del modulo.
    app()->forgetInstance(ReviewableRegistry::class);
    app()->singleton(ReviewableRegistry::class, fn (): ReviewableRegistry => new ReviewableRegistry);

    $processed = app(CampaignEngine::class)->close($c);

    expect($processed)->toBe(0)
        ->and(ReviewItem::query()->firstOrFail()->decision)->toBe('pending')
        ->and($c->fresh()->status)->toBe('completed');
});

it('un item non revocabile è auditato come tale, non ignorato in silenzio', function () {
    registerFake(new FakeReviewableSource(['acc_1']));
    $c = polyCampaign(['scope_json' => ['reviewable_types' => ['fake_access']]]);
    app(CampaignEngine::class)->open($c);

    app()->forgetInstance(ReviewableRegistry::class);
    app()->singleton(ReviewableRegistry::class, fn (): ReviewableRegistry => new ReviewableRegistry);
    app(CampaignEngine::class)->close($c);

    $event = AuditEvent::query()->where('event_type', 'iam.access_review.item_unrevocable')->first();
    expect($event)->not->toBeNull()
        ->and($event->metadata_json['reviewable_type'])->toBe('fake_access');
});

it('un item orfano non blocca la chiusura degli altri', function () {
    registerFake(new FakeReviewableSource(['acc_1']));
    $grant = polyGrant();
    $c = polyCampaign(['scope_json' => ['reviewable_types' => ['grant', 'fake_access']]]);
    app(CampaignEngine::class)->open($c);

    // Registro con il solo built-in: la sorgente del modulo è sparita.
    app()->forgetInstance(ReviewableRegistry::class);
    app()->singleton(ReviewableRegistry::class, function (): ReviewableRegistry {
        $registry = new ReviewableRegistry;
        $registry->register(new GrantReviewableSource);

        return $registry;
    });

    $processed = app(CampaignEngine::class)->close($c);

    expect($processed)->toBe(1)
        ->and($grant->fresh()->revoked_at)->not->toBeNull()
        ->and(ReviewItem::query()->where('reviewable_type', 'fake_access')->firstOrFail()->decision)->toBe('pending');
});

it('un reviewable_types che nomina una sorgente assente non fa fallire l\'apertura', function () {
    polyGrant();
    $c = polyCampaign(['scope_json' => ['reviewable_types' => ['grant', 'mai_registrata']]]);

    expect(app(CampaignEngine::class)->open($c))->toBe(1);
});

it('la sorgente built-in dei grant è registrata di default', function () {
    expect(app(ReviewableRegistry::class)->for('grant'))->toBeInstanceOf(GrantReviewableSource::class)
        ->and(app(ReviewableRegistry::class)->types())->toContain('grant');
});
