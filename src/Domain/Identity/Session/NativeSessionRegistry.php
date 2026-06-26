<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Identity\Session;

use Illuminate\Support\Carbon;
use Padosoft\Iam\Contracts\Identity\SessionMeta;
use Padosoft\Iam\Contracts\Identity\SessionRef;
use Padosoft\Iam\Contracts\Identity\SessionRegistry;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Iam\Domain\Identity\Models\Session;

/**
 * Registry sessioni nativo su iam_sessions (doc 10 §3/§4). Idle timeout da config
 * (iam.authentication.session.idle_timeout); absolute timeout fissato all'apertura e mai esteso.
 */
final class NativeSessionRegistry implements SessionRegistry
{
    public function start(SubjectRef $subject, SessionMeta $meta): SessionRef
    {
        $now = Carbon::now();
        $session = Session::query()->create([
            'user_id' => $subject->id,
            'organization_id' => $meta->organizationId,
            'aal' => $meta->aal->value,
            'last_activity_at' => $now,
            'absolute_expires_at' => $now->copy()->addSeconds(max(1, $meta->absoluteTimeout)),
            'device_fingerprint_hash' => $meta->deviceFingerprintHash,
            'ip_hash' => $meta->ipHash,
            'user_agent_hash' => $meta->userAgentHash,
        ]);

        return new SessionRef($session->id);
    }

    public function touch(SessionRef $session): void
    {
        $model = $this->find($session->id);
        if ($model === null || !$this->isActive($model)) {
            return; // non estendere una sessione scaduta/revocata
        }
        $model->forceFill(['last_activity_at' => Carbon::now()])->save();
    }

    public function active(string $sessionId): bool
    {
        $model = $this->find($sessionId);

        return $model !== null && $this->isActive($model);
    }

    public function revokeSession(string $sessionId, string $reason): void
    {
        $this->find($sessionId)?->markRevoked($reason);
    }

    public function revokeAllForSubject(SubjectRef $subject, string $reason): void
    {
        Session::query()
            ->where('user_id', $subject->id)
            ->whereNull('revoked_at')
            ->update(['revoked_at' => Carbon::now(), 'revoked_reason' => $reason !== '' ? $reason : 'revoked']);
    }

    /**
     * @return array<int, SessionRef>
     */
    public function listForSubject(SubjectRef $subject): iterable
    {
        return Session::query()
            ->where('user_id', $subject->id)
            ->whereNull('revoked_at')
            ->get()
            ->filter(fn (Session $s): bool => $this->isActive($s))
            ->map(fn (Session $s): SessionRef => new SessionRef($s->id))
            ->values()
            ->all();
    }

    private function find(string $sessionId): ?Session
    {
        return $sessionId === '' ? null : Session::query()->whereKey($sessionId)->first();
    }

    private function isActive(Session $session): bool
    {
        if ($session->revoked_at !== null) {
            return false;
        }
        $now = Carbon::now();
        if ($now->greaterThanOrEqualTo($session->absolute_expires_at)) {
            return false; // absolute timeout (mai esteso)
        }

        // Idle timeout: ultima attività + finestra idle deve essere nel futuro.
        return $session->last_activity_at->copy()->addSeconds($this->idleTimeout())->greaterThan($now);
    }

    private function idleTimeout(): int
    {
        $value = config('iam.authentication.session.idle_timeout', 1800);

        return is_int($value) && $value > 0 ? $value : 1800;
    }
}
