<?php

declare(strict_types=1);

namespace Padosoft\Iam\Http\Admin\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Padosoft\Iam\Domain\Governance\Recommendations\LeastPrivilegeRecommender;
use Padosoft\Iam\Http\Admin\AdminController;

/**
 * Admin API — Least-privilege / anomaly recommendations (doc 16 §3, doc 14 §7). Espone il recommender
 * deterministico (M8.5): SOLO proposte (draft), mai azioni. Lo scope è l'org dell'attore (un admin
 * vincolato a un tenant vede solo le raccomandazioni di quel tenant).
 */
final class RecommendationsController extends AdminController
{
    public function __construct(private readonly LeastPrivilegeRecommender $recommender) {}

    public function leastPrivilege(Request $request): JsonResponse
    {
        $recommendations = $this->recommender->analyze($this->context($request)->organizationId);

        return $this->ok([
            'recommendations' => array_map(static fn ($r): array => $r->toArray(), $recommendations),
            'count' => count($recommendations),
        ]);
    }
}
