<?php

declare(strict_types=1);

namespace Padosoft\Iam\Http\Admin\Controllers;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Padosoft\Iam\Domain\Governance\Reviews\CampaignEngine;
use Padosoft\Iam\Domain\Governance\Reviews\Models\ReviewCampaign;
use Padosoft\Iam\Domain\Governance\Reviews\Models\ReviewItem;
use Padosoft\Iam\Http\Admin\AdminController;
use Padosoft\Iam\Http\Admin\Support\ApiProblemException;

/**
 * Admin API — Access Reviews / Certification (doc 16 §3, doc 14 §3). Espone il campaign engine
 * (M8.3): creazione/apertura/chiusura campagne e certificazione (approve)/revoca dei singoli item.
 * Ogni azione che muta un grant è già auditata dal dominio; qui si aggiunge l'audit admin con l'attore.
 */
final class AccessReviewsController extends AdminController
{
    public function __construct(private readonly CampaignEngine $engine) {}

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

        return $this->paginate(
            ReviewItem::query()->where('campaign_id', $model->id),
            $request,
            fn (Model $i): array => $i instanceof ReviewItem ? $this->itemSummary($i) : [],
        );
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

        return $this->ok($this->itemSummary($model->fresh() ?? $model));
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
     * @return array<string, mixed>
     */
    private function itemSummary(ReviewItem $i): array
    {
        return [
            'id' => $i->id, 'campaign_id' => $i->campaign_id, 'grant_id' => $i->grant_id,
            'reviewer_subject' => $i->reviewer_subject, 'decision' => $i->decision,
            'signals' => $i->signals_json, 'decided_by' => $i->decided_by,
        ];
    }
}
