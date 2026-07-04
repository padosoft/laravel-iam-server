<?php

declare(strict_types=1);

namespace Padosoft\Iam\Http\Admin\Controllers;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Padosoft\Iam\Contracts\Identity\SessionRegistry;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Iam\Domain\Audit\Pii\PrivacyMode;
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
            // console-friendly alias for the grid's "last active" column (privacy: IP/UA are hashed only).
            'last_active_at' => $s->last_activity_at->toIso8601String(),
            'step_up_at' => $s->step_up_at?->toIso8601String(),
            // Privacy: IP/UA are stored only as salted one-way hashes. Expose a short prefix as a
            // non-reversible "device tag" so an operator can tell sessions/devices apart. Prefer the
            // device fingerprint when present, else fall back to the user-agent hash (the login flow
            // always captures a UA but only sets a fingerprint if the client sends one).
            'device_tag' => (function () use ($s): ?string {
                $value = $s->getAttribute('device_fingerprint_hash');
                if (!is_string($value)) {
                    $value = $s->getAttribute('user_agent_hash');
                }
                if (!is_string($value)) {
                    return null;
                }
                // Keep the tag non-reversible even in `full` mode (where user_agent_hash holds the clear
                // UA): if the stored value isn't already a digest, hash it before taking the prefix.
                $hash = preg_match('/^[0-9a-f]{64}$/i', $value) === 1 ? $value : PrivacyMode::hash($value);

                return is_string($hash) ? substr($hash, 0, 10) : null;
            })(),
            // Readable IP/UA are exposed ONLY when iam.audit.ip_mode/ua_mode = full (forensics); in the
            // default `hash` mode the columns hold one-way hashes, so we never surface them as ip/user_agent.
            'ip' => $this->readable($s->getAttribute('ip_hash'), 'ip_mode'),
            'user_agent' => $this->readable($s->getAttribute('user_agent_hash'), 'ua_mode'),
            'created_at' => $s->created_at?->toIso8601String(),
            'absolute_expires_at' => $s->absolute_expires_at->toIso8601String(),
            // Idle window (seconds): the console computes idle expiry as last_activity_at + idle_timeout.
            'idle_timeout' => $s->idle_timeout,
            'revoked_at' => $s->revoked_at?->toIso8601String(),
            'revoked_reason' => $s->revoked_reason,
        ];
    }

    /**
     * Surface a stored IP/UA only in `full` mode (clear value); in `hash`/`none` mode return null.
     * Guards the write-time/read-time mode-flip hazard: a value written under `hash` is a 64-hex digest,
     * so never surface that as a clear ip/user_agent even if the mode was later flipped to `full`.
     */
    private function readable(mixed $value, string $modeKey): ?string
    {
        if (config('iam.audit.'.$modeKey, 'hash') !== 'full' || !is_string($value)) {
            return null;
        }

        return preg_match('/^[0-9a-f]{64}$/i', $value) === 1 ? null : $value;
    }
}
