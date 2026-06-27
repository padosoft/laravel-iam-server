<?php

declare(strict_types=1);

namespace Padosoft\Iam\Http\Admin\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Padosoft\Iam\Domain\Audit\AuditChainVerifier;
use Padosoft\Iam\Domain\Audit\Events\EventsQuery;
use Padosoft\Iam\Domain\Audit\Models\AuditEvent;
use Padosoft\Iam\Http\Admin\AdminController;

/**
 * Admin API — Audit events + verifica catena (doc 16 §3, doc 12). Lettura cursor-based degli eventi
 * sigillati e verifica on-demand della hash-chain tamper-evident (per gli auditor: la prova che il
 * registro non è stato alterato). Sola lettura: l'audit è append-only, non si muta via API.
 */
final class AuditController extends AdminController
{
    public function __construct(
        private readonly EventsQuery $events,
        private readonly AuditChainVerifier $verifier,
    ) {}

    public function eventsIndex(Request $request): JsonResponse
    {
        $stream = is_string($request->query('stream')) && $request->query('stream') !== '' ? $request->query('stream') : 'global';
        $cursor = is_string($request->query('cursor')) ? $request->query('cursor') : null;
        $typePrefix = is_string($request->query('type')) ? $request->query('type') : null;
        $limit = is_numeric($request->query('limit')) ? max(1, min(200, (int) $request->query('limit'))) : 50;

        $page = $this->events->page($stream, $limit, $cursor, $typePrefix);

        return new JsonResponse([
            'data' => array_map(fn (AuditEvent $e): array => $this->summary($e), $page->events),
            'next_cursor' => $page->nextCursor,
        ]);
    }

    public function verifyChain(Request $request): JsonResponse
    {
        $stream = is_string($request->query('stream')) && $request->query('stream') !== '' ? $request->query('stream') : 'global';
        $result = $this->verifier->verify($stream);

        return $this->ok([
            'stream' => $stream,
            'valid' => $result->valid,
            'checked' => $result->checked,
            'first_broken_uuid' => $result->firstBrokenUuid,
            'reason' => $result->reason,
            'cause' => $result->cause,
        ]);
    }

    /**
     * @return array<string, mixed>
     */
    private function summary(AuditEvent $e): array
    {
        return [
            'id' => $e->getKey(),
            'seq' => $e->getAttribute('seq'),
            'stream' => $e->stream,
            'event_type' => $e->event_type,
            'target_type' => $e->getAttribute('target_type'),
            'target_id' => $e->getAttribute('target_id'),
            'organization_id' => $e->getAttribute('organization_id'),
            'occurred_at' => $e->occurred_at->toIso8601String(),
        ];
    }
}
