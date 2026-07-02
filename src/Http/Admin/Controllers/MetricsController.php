<?php

declare(strict_types=1);

namespace Padosoft\Iam\Http\Admin\Controllers;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\DB;
use Padosoft\Iam\Domain\Audit\Models\AuditEvent;
use Padosoft\Iam\Domain\Authorization\Models\Grant;
use Padosoft\Iam\Domain\Identity\Models\Session;
use Padosoft\Iam\Domain\Identity\Models\User;
use Padosoft\Iam\Domain\Organizations\Models\Membership;
use Padosoft\Iam\Http\Admin\AdminController;

/**
 * Admin API — Metrics (doc 16 §3.1, doc 19 §8). SOLO controller, read-only: aggregazioni cursor-free su
 * una finestra temporale (`?from=&to=&app=`), tenant-scoped. BOUNDED by design: ogni query è una
 * COUNT/GROUP BY indicizzata con finestra obbligatoria (default 30 giorni) e top-N limitato — mai un
 * full-scan non vincolato. Nessuna mutazione, nessun audit.
 */
final class MetricsController extends AdminController
{
    /** Finestra di default (giorni) quando `from` non è passato: garantisce query bounded. */
    private const DEFAULT_WINDOW_DAYS = 30;

    /** Cap dei gruppi restituiti (top-N) per non spedire cardinalità illimitata. */
    private const TOP_N = 20;

    /** Soglia (giorni) oltre cui un grant è considerato "stale" (tie con least-privilege M9). */
    private const STALE_DAYS = 90;

    public function decisions(Request $request): JsonResponse
    {
        [$from, $to] = $this->window($request);
        $org = $this->context($request)->organizationId;
        $app = $this->stringQuery($request, 'app');

        $base = fn (): Builder => $this->auditWindow($from, $to, $org, $app);

        // allow/deny: derivati dal suffisso dell'event_type (.denied/.rejected = deny). Senza un decision
        // log dedicato, l'audit append-only è la fonte di verità bounded più vicina.
        $denied = (clone $base())->where(function (Builder $q): void {
            $q->where('event_type', 'like', '%.denied')->orWhere('event_type', 'like', '%.rejected');
        })->count();
        $total = $base()->count();

        return $this->ok([
            // Stima derivata dagli eventi di audit (non un decision-log dedicato del PDP): allow/deny
            // sono inferiti dal suffisso event_type. Per dashboard, non per conteggi PDP esatti.
            'source' => 'audit_events_estimate',
            'window' => ['from' => $from->toIso8601String(), 'to' => $to->toIso8601String()],
            'total' => $total,
            'allow' => max(0, $total - $denied),
            'deny' => $denied,
            'top_denied' => $this->groupCount((clone $base())->where('event_type', 'like', '%.denied'), 'event_type'),
            'step_up' => (clone $base())->whereNotNull('actor_assurance')->count(),
            'by_event_type' => $this->groupCount($base(), 'event_type'),
        ]);
    }

    public function grants(Request $request): JsonResponse
    {
        $org = $this->context($request)->organizationId;
        $scoped = fn (): Builder => Grant::query()->when($org !== null, fn (Builder $q) => $q->where('organization_id', $org));

        $staleBefore = now()->subDays(self::STALE_DAYS);

        return $this->ok([
            'active' => (clone $scoped())->active()->count(),
            'revoked' => (clone $scoped())->whereNotNull('revoked_at')->count(),
            'expired' => (clone $scoped())->whereNull('revoked_at')->whereNotNull('valid_until')->where('valid_until', '<', now())->count(),
            'privileged' => (clone $scoped())->active()->where('is_privileged', true)->count(),
            // stale: attivi mai usati o non usati da oltre STALE_DAYS → candidati least-privilege.
            'stale' => (clone $scoped())->active()->where(function (Builder $q) use ($staleBefore): void {
                $q->whereNull('last_used_at')->orWhere('last_used_at', '<', $staleBefore);
            })->count(),
        ]);
    }

    /**
     * User inventory + login activity (doc 16 §3.1). Counts over the identity store (total + by status)
     * and live sessions, plus login/step-up activity derived from the audit stream (the host emits
     * `auth.login.succeeded|failed` / `auth.stepup.failed`). Tenant-scoped: an org-bound admin sees only
     * users that are members of its org; a global admin sees the whole store. Bounded like the others.
     */
    public function users(Request $request): JsonResponse
    {
        [$from, $to] = $this->window($request);
        $org = $this->context($request)->organizationId;

        $scoped = fn (): Builder => User::query()->when(
            $org !== null,
            fn (Builder $q) => $q->whereIn('id', Membership::query()->where('organization_id', $org)->select('user_id')),
        );

        $byStatus = [];
        foreach (['active', 'suspended', 'deactivated'] as $status) {
            $byStatus[$status] = (clone $scoped())->where('status', $status)->count();
        }

        // Distinct users with at least one live (non-revoked, not past absolute timeout) session — a
        // user with N sessions counts once, hence the explicit key name.
        $usersWithActiveSessions = Session::query()
            ->whereNull('revoked_at')
            ->where('absolute_expires_at', '>', now())
            ->when($org !== null, fn (Builder $q) => $q->where('organization_id', $org))
            ->distinct()
            ->count('user_id');

        // Login activity from the audit stream. Counts + last_login_at are within the metrics window
        // (bounded, consistent with the sibling endpoints; the window is echoed in the response). The
        // host emits auth.login.*/auth.stepup.* — global events, so an org-bound admin sees them only if
        // the emitter tags organization_id; the console operates as a global admin (org null), so it does.
        $logins = fn (string $type): int => $this->auditWindow($from, $to, $org, null)
            ->where('event_type', $type)->count();
        $lastLogin = $this->auditWindow($from, $to, $org, null)
            ->where('event_type', 'auth.login.succeeded')->max('occurred_at');

        return $this->ok([
            'window' => ['from' => $from->toIso8601String(), 'to' => $to->toIso8601String()],
            'total' => $scoped()->count(),
            'by_status' => $byStatus,
            'users_with_active_sessions' => $usersWithActiveSessions,
            'logins' => [
                'succeeded' => $logins('auth.login.succeeded'),
                'failed' => $logins('auth.login.failed'),
                'step_up_failed' => $logins('auth.stepup.failed'),
                'last_login_at' => is_string($lastLogin) ? Carbon::parse($lastLogin)->toIso8601String() : null,
            ],
        ]);
    }

    public function auditMetrics(Request $request): JsonResponse
    {
        [$from, $to] = $this->window($request);
        $org = $this->context($request)->organizationId;
        $app = $this->stringQuery($request, 'app');

        // Integrità catena: ultimo checkpoint firmato per gli stream dell'org (o globale).
        $lastCheckpoint = DB::table('iam_audit_checkpoints')
            ->when($org !== null, fn ($q) => $q->where('stream', $org))
            ->orderByDesc('signed_at')
            ->first();

        // Outbox lag: messaggi non ancora consegnati (bounded COUNT).
        $outboxPending = DB::table('iam_outbox')
            ->where('status', 'pending')
            ->when($org !== null, fn ($q) => $q->where('stream', $org))
            ->count();

        return $this->ok([
            'window' => ['from' => $from->toIso8601String(), 'to' => $to->toIso8601String()],
            'total' => $this->auditWindow($from, $to, $org, $app)->count(),
            'by_event_type' => $this->groupCount($this->auditWindow($from, $to, $org, $app), 'event_type'),
            'by_risk_level' => $this->groupCount($this->auditWindow($from, $to, $org, $app), 'risk_level'),
            'integrity' => [
                'last_checkpoint_at' => is_string($lastCheckpoint?->signed_at) ? $lastCheckpoint->signed_at : null,
                'last_checkpoint_seq' => is_numeric($lastCheckpoint?->up_to_seq) ? (int) $lastCheckpoint->up_to_seq : null,
            ],
            'outbox_lag' => $outboxPending,
        ]);
    }

    /**
     * @return Builder<AuditEvent>
     */
    private function auditWindow(Carbon $from, Carbon $to, ?string $org, ?string $app): Builder
    {
        return AuditEvent::query()
            ->whereBetween('occurred_at', [$from, $to])
            ->when($org !== null, fn (Builder $q) => $q->where('organization_id', $org))
            ->when($app !== null, fn (Builder $q) => $q->where('application_id', $app));
    }

    /**
     * GROUP BY bounded su una colonna → top-N coppie {value: count}. Portabile (selectRaw count).
     *
     * @param  Builder<AuditEvent>  $query
     * @return array<string, int>
     */
    private function groupCount(Builder $query, string $column): array
    {
        /** @var Collection<int, object> $rows */
        $rows = $query->getQuery()
            ->select($column, DB::raw('count(*) as aggregate'))
            ->groupBy($column)
            ->orderByDesc('aggregate')
            ->limit(self::TOP_N)
            ->get();

        $out = [];
        foreach ($rows as $row) {
            $key = $row->{$column} ?? null;
            if (is_scalar($key)) {
                $out[(string) $key] = is_numeric($row->aggregate ?? null) ? (int) $row->aggregate : 0;
            }
        }

        return $out;
    }

    /**
     * Finestra temporale obbligatoria (bounded). `from` default = now - DEFAULT_WINDOW_DAYS; `to` default
     * = now. Date malformate → default, mai una finestra aperta.
     *
     * @return array{0: Carbon, 1: Carbon}
     */
    private function window(Request $request): array
    {
        $from = $this->parseDate($this->stringQuery($request, 'from')) ?? now()->subDays(self::DEFAULT_WINDOW_DAYS);
        $to = $this->parseDate($this->stringQuery($request, 'to')) ?? now();
        if ($from->greaterThan($to)) {
            [$from, $to] = [$to, $from];
        }

        return [$from, $to];
    }

    private function parseDate(?string $value): ?Carbon
    {
        if ($value === null) {
            return null;
        }
        try {
            return Carbon::parse($value);
        } catch (\Throwable) {
            return null;
        }
    }

    private function stringQuery(Request $request, string $key): ?string
    {
        $value = $request->query($key);

        return is_string($value) && $value !== '' ? $value : null;
    }
}
