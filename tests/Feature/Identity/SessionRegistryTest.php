<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Padosoft\Iam\Contracts\Assurance\Aal;
use Padosoft\Iam\Contracts\Identity\SessionMeta;
use Padosoft\Iam\Contracts\Identity\SessionRef;
use Padosoft\Iam\Contracts\Identity\SessionRegistry;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Iam\Domain\Identity\Models\Session;
use Padosoft\Iam\Domain\Identity\Models\User;

uses(RefreshDatabase::class);

function sessionUser(): SubjectRef
{
    $user = new User;
    $user->forceFill(['email' => 'u@test.local'])->save();

    return new SubjectRef('user', $user->id);
}

function registry(): SessionRegistry
{
    return app(SessionRegistry::class);
}

it('apre una sessione attiva e ne ritorna il sid', function () {
    $subject = sessionUser();
    $ref = registry()->start($subject, new SessionMeta(aal: Aal::AAL1));

    expect($ref)->toBeInstanceOf(SessionRef::class)
        ->and($ref->id)->toBeString()->not->toBe('')
        ->and(registry()->active($ref->id))->toBeTrue();
});

it('revoca una sessione → non più attiva', function () {
    $ref = registry()->start(sessionUser(), new SessionMeta);

    registry()->revokeSession($ref->id, 'logout');

    expect(registry()->active($ref->id))->toBeFalse();
});

it('revoca tutte le sessioni del soggetto', function () {
    $subject = sessionUser();
    $a = registry()->start($subject, new SessionMeta);
    $b = registry()->start($subject, new SessionMeta);

    registry()->revokeAllForSubject($subject, 'password_change');

    expect(registry()->active($a->id))->toBeFalse()
        ->and(registry()->active($b->id))->toBeFalse();
});

it('un sid sconosciuto non è attivo (fail-closed)', function () {
    expect(registry()->active('non-esiste'))->toBeFalse()
        ->and(registry()->active(''))->toBeFalse();
});

it('idle timeout: una sessione inattiva oltre la finestra scade; touch la rinnova', function () {
    $ref = registry()->start(sessionUser(), new SessionMeta(idleTimeout: 60));

    $this->travel(30)->seconds();
    registry()->touch($ref);     // rinnova l'idle (last_activity = now)

    $this->travel(40)->seconds(); // 40s dall'ultimo touch (<60) → ancora attiva
    expect(registry()->active($ref->id))->toBeTrue();

    $this->travel(70)->seconds(); // 110s dall'ultimo touch (>60) → idle scaduto
    expect(registry()->active($ref->id))->toBeFalse();
});

it('absolute timeout: non estendibile nemmeno con touch', function () {
    $ref = registry()->start(sessionUser(), new SessionMeta(absoluteTimeout: 2));

    $this->travel(5)->seconds();
    registry()->touch($ref);     // no-op: oltre l'absolute timeout

    expect(registry()->active($ref->id))->toBeFalse();
});

it('absolute_expires_at non è estendibile via mass-assignment (fill)', function () {
    $ref = registry()->start(sessionUser(), new SessionMeta(absoluteTimeout: 60));
    $original = Session::query()->whereKey($ref->id)->value('absolute_expires_at');

    // Un fill() malevolo NON deve poter spostare in avanti l'absolute timeout.
    Session::query()->whereKey($ref->id)->first()
        ?->fill(['absolute_expires_at' => now()->addYears(1)])->save();

    $after = Session::query()->whereKey($ref->id)->value('absolute_expires_at');
    expect($after->equalTo($original))->toBeTrue();
});

it('listForSubject ritorna solo le sessioni attive', function () {
    $subject = sessionUser();
    $active = registry()->start($subject, new SessionMeta);
    $revoked = registry()->start($subject, new SessionMeta);
    registry()->revokeSession($revoked->id, 'device_removed');

    $ids = array_map(static fn (SessionRef $r): string => $r->id, [...registry()->listForSubject($subject)]);

    expect($ids)->toContain($active->id)->not->toContain($revoked->id);
});
