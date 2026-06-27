<?php

declare(strict_types=1);

namespace Padosoft\Iam\Http\Admin\Controllers;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Padosoft\Iam\Contracts\Identity\SessionRegistry;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Iam\Domain\Identity\Models\Session;
use Padosoft\Iam\Http\Admin\AdminController;
use Padosoft\Iam\Http\Admin\Support\ApiProblemException;

/**
 * Admin API — Sessions (doc 16 §3.16). Lista/dettaglio delle sessioni server-side e revoca
 * (singola o tutte quelle di un utente). La revoca passa SEMPRE dal SessionRegistry (autorità del
 * lifecycle, idempotente) e viene auditata. Tenant scoping per `organization_id`.
 */
final class SessionsController extends AdminController
{
    public function __construct(private readonly SessionRegistry $registry) {}

    public function index(Request $request): JsonResponse
    {
        $query = Session::query();
        $org = $this->context($request)->organizationId;
        if ($org !== null) {
            $query->where('organization_id', $org);
        }
        if (is_string($request->query('user')) && $request->query('user') !== '') {
            $query->where('user_id', $request->query('user'));
        }

        return $this->paginate($query, $request, fn (Model $s): array => $s instanceof Session ? $this->summary($s) : []);
    }

    public function show(Request $request, string $session): JsonResponse
    {
        return $this->ok($this->summary($this->find($request, $session)));
    }

    public function revoke(Request $request, string $session): JsonResponse
    {
        $model = $this->find($request, $session);
        $reason = $request->input('reason');
        $reason = is_string($reason) && $reason !== '' ? $reason : 'admin-revoke';

        $this->registry->revokeSession($model->id, $reason);
        $this->audit($request, 'iam.session.revoked', 'session', $model->id, ['reason' => $reason]);

        return $this->ok($this->summary($model->fresh() ?? $model));
    }

    public function revokeAllForUser(Request $request, string $user): JsonResponse
    {
        // Tenant scoping: un admin GLOBALE (org del token null = super-admin) revoca tutte le sessioni
        // del soggetto; un admin vincolato a un'org revoca SOLO le sessioni di quel tenant.
        $org = $this->context($request)->organizationId;
        $active = Session::query()
            ->where('user_id', $user)
            ->whereNull('revoked_at')
            ->when($org !== null, fn ($q) => $q->where('organization_id', $org))
            ->get();

        if ($org === null) {
            $this->registry->revokeAllForSubject(new SubjectRef('user', $user), 'admin-revoke-all');
        } else {
            // Il registry revoca per soggetto globale; qui restiamo scoped revocando solo le sessioni del tenant.
            foreach ($active as $s) {
                $this->registry->revokeSession($s->id, 'admin-revoke-all');
            }
        }

        $count = $active->count();
        $this->audit($request, 'iam.session.revoked_all', 'user', $user, ['revoked' => $count]);

        return $this->ok(['user_id' => $user, 'revoked' => $count]);
    }

    private function find(Request $request, string $session): Session
    {
        $model = Session::query()->find($session);
        $org = $this->context($request)->organizationId;
        if ($model === null || ($org !== null && $model->organization_id !== $org)) {
            throw ApiProblemException::notFound("Sessione \"{$session}\" non trovata.");
        }

        return $model;
    }

    /**
     * @return array<string, mixed>
     */
    private function summary(Session $s): array
    {
        return [
            'id' => $s->id,
            'user_id' => $s->user_id,
            'organization_id' => $s->organization_id,
            'aal' => $s->aal,
            'last_activity_at' => $s->last_activity_at->toIso8601String(),
            'absolute_expires_at' => $s->absolute_expires_at->toIso8601String(),
            'revoked_at' => $s->revoked_at?->toIso8601String(),
        ];
    }
}
