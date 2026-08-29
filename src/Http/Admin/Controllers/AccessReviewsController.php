<?php

declare(strict_types=1);

namespace Padosoft\Iam\Http\Admin\Controllers;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Padosoft\Iam\Domain\Governance\Reviews\CampaignEngine;
use Padosoft\Iam\Domain\Governance\Reviews\Models\ReviewCampaign;
use Padosoft\Iam\Domain\Governance\Reviews\Models\ReviewItem;
use Padosoft\Iam\Domain\Governance\Reviews\Reviewable\ReviewableRegistry;
use Padosoft\Iam\Http\Admin\AdminController;
use Padosoft\Iam\Http\Admin\Support\ApiProblemException;

/**
 * Admin API — Access Reviews / Certification (doc 16 §3, doc 14 §3). Espone il campaign engine
 * (M8.3): creazione/apertura/chiusura campagne e certificazione (approve)/revoca dei singoli item.
 * Ogni azione che muta un grant è già auditata dal dominio; qui si aggiunge l'audit admin con l'attore.
 */
final class AccessReviewsController extends AdminController
{
    public function __construct(
        private readonly CampaignEngine $engine,
        private readonly ReviewableRegistry $reviewables,
    ) {}

    public function index(Request $request): JsonResponse
    {
        $query = ReviewCampaign::query();
        $org = $this->context($request)->organizationId;
        if ($org !== null) {
            $query->where('organization_id', $org);
        }
        if (is_string($request->query('status')) && $request->query('status') !== '') {
            $query->where('status', $request->query('status'));
        }

        return $this->paginate($query, $request, fn (Model $c): array => $c instanceof ReviewCampaign ? $this->campaignSummary($c) : []);
    }

    public function store(Request $request): JsonResponse
    {
        $name = $request->input('name');
        if (!is_string($name) || $name === '') {
            throw ApiProblemException::unprocessable('Campo name obbligatorio.', ['name' => ['name è obbligatorio']]);
        }
        $scope = $request->input('scope_json');
        $strategy = $request->input('reviewer_strategy');
        $onUnconfirmed = $request->input('on_unconfirmed');

        $campaign = ReviewCampaign::create([
            'organization_id' => $this->context($request)->organizationId,
            'name' => $name,
            'scope_json' => is_array($scope) ? $scope : null,
            'reviewer_strategy' => is_string($strategy) && $strategy !== '' ? $strategy : 'named',
            'on_unconfirmed' => in_array($onUnconfirmed, ['revoke', 'keep', 'suspend'], true) ? $onUnconfirmed : 'revoke',
            'due_at' => $request->input('due_at'),
            'created_by' => $this->context($request)->actorRef(),
        ]);

        $this->audit($request, 'iam.access_review.campaign_created', 'review_campaign', $campaign->id, ['name' => $name]);

        return $this->ok($this->campaignSummary($campaign), 201);
    }

    public function open(Request $request, string $campaign): JsonResponse
    {
        $model = $this->findCampaign($request, $campaign);
        $created = $this->runDomain(fn (): int => $this->engine->open($model));
        $this->audit($request, 'iam.access_review.opened', 'review_campaign', $model->id, ['items_created' => $created]);

        return $this->ok(['campaign_id' => $model->id, 'items_created' => $created, 'status' => $model->fresh()?->status]);
    }

    public function close(Request $request, string $campaign): JsonResponse
    {
        $model = $this->findCampaign($request, $campaign);
        $processed = $this->runDomain(fn (): int => $this->engine->close($model));
        $this->audit($request, 'iam.access_review.closed', 'review_campaign', $model->id, ['processed' => $processed]);

        return $this->ok(['campaign_id' => $model->id, 'processed' => $processed, 'status' => $model->fresh()?->status]);
    }

    public function items(Request $request, string $campaign): JsonResponse
    {
        $model = $this->findCampaign($request, $campaign);

        // L'oggetto certificato è polimorfico: niente eager-load di una relazione Eloquent. I campi
        // di riepilogo si chiedono alle sorgenti IN BLOCCO sulla pagina già materializzata — una
        // query per tipo presente nella pagina, non una per item.
        $descriptions = [];

        return $this->paginate(
            ReviewItem::query()->where('campaign_id', $model->id),
            $request,
            // Closure (non arrow fn) con `use (&$descriptions)`: una arrow fn catturerebbe l'array
            // PER VALORE al momento della creazione, cioè ancora vuoto, e ogni item uscirebbe senza
            // i campi della propria sorgente.
            function (Model $i) use (&$descriptions): array {
                return $i instanceof ReviewItem ? $this->itemSummary($i, $descriptions) : [];
            },
            'id',
            function (Collection $rows) use (&$descriptions): void {
                $descriptions = $this->describeFor($rows->filter(fn (Model $r): bool => $r instanceof ReviewItem)->all());
            },
        );
    }

    public function cancel(Request $request, string $campaign): JsonResponse
    {
        $model = $this->findCampaign($request, $campaign);
        $this->runDomain(fn () => $this->engine->cancel($model));
        $this->audit($request, 'iam.access_review.cancelled', 'review_campaign', $model->id);

        return $this->ok(['campaign_id' => $model->id, 'status' => $model->fresh()?->status]);
    }

    public function certify(Request $request, string $item): JsonResponse
    {
        return $this->decide($request, $item, 'approved');
    }

    public function revoke(Request $request, string $item): JsonResponse
    {
        return $this->decide($request, $item, 'revoked');
    }

    private function decide(Request $request, string $item, string $decision): JsonResponse
    {
        $model = $this->findItem($request, $item);
        $note = $request->input('note');
        $this->runDomain(fn () => $this->engine->decide($model, $decision, $this->context($request)->actorRef(), is_string($note) ? $note : null));
        $this->audit($request, 'iam.access_review.item_decided', 'review_item', $model->id, ['decision' => $decision]);

        $fresh = $model->fresh() ?? $model;

        return $this->ok($this->itemSummary($fresh, $this->describeFor([$fresh])));
    }

    private function findCampaign(Request $request, string $id): ReviewCampaign
    {
        $model = ReviewCampaign::query()->find($id);
        $org = $this->context($request)->organizationId;
        if ($model === null || ($org !== null && $model->organization_id !== $org)) {
            throw ApiProblemException::notFound("Campagna \"{$id}\" non trovata.");
        }

        return $model;
    }

    private function findItem(Request $request, string $id): ReviewItem
    {
        $model = ReviewItem::query()->find($id);
        if ($model === null) {
            throw ApiProblemException::notFound("Item \"{$id}\" non trovato.");
        }
        // Tenant scoping via la campagna dell'item.
        $this->findCampaign($request, $model->campaign_id);

        return $model;
    }

    /**
     * @return array<string, mixed>
     */
    private function campaignSummary(ReviewCampaign $c): array
    {
        return [
            'id' => $c->id, 'name' => $c->name, 'status' => $c->status,
            'reviewer_strategy' => $c->reviewer_strategy, 'on_unconfirmed' => $c->on_unconfirmed,
            'organization_id' => $c->organization_id, 'due_at' => $c->due_at?->toIso8601String(),
        ];
    }

    /**
     * Campi di riepilogo per un insieme di item, una chiamata per sorgente presente.
     *
     * @param  iterable<ReviewItem>  $items
     * @return array<string, array<string, mixed>> "type:id" => campi
     */
    private function describeFor(iterable $items): array
    {
        $byType = [];
        foreach ($items as $item) {
            $byType[$item->reviewable_type][] = $item->reviewable_id;
        }

        $out = [];
        foreach ($byType as $type => $ids) {
            $source = $this->reviewables->for($type);
            if ($source === null) {
                continue; // modulo non installato: l'item resta visibile, senza dettagli
            }
            foreach ($source->describeMany(array_values(array_unique($ids))) as $id => $fields) {
                $out[$type.':'.$id] = $fields;
            }
        }

        return $out;
    }

    /**
     * @param  array<string, array<string, mixed>>  $descriptions
     * @return array<string, mixed>
     */
    private function itemSummary(ReviewItem $i, array $descriptions): array
    {
        // La sorgente dice CHI ha CHE COSA: per un grant è subject/privilege, per una delegation
        // grant è utente/agente/scope. Il console renderizza quello che arriva, senza sapere il tipo.
        $fields = $descriptions[$i->reviewable_type.':'.$i->reviewable_id] ?? [];

        return [
            'id' => $i->id, 'campaign_id' => $i->campaign_id,
            'reviewable_type' => $i->reviewable_type, 'reviewable_id' => $i->reviewable_id,
            'reviewer_subject' => $i->reviewer_subject, 'decision' => $i->decision,
            'signals' => $i->signals_json, 'decided_by' => $i->decided_by,
        ] + $fields;
    }
}
