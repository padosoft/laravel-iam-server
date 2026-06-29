<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Padosoft\Iam\Contracts\Assurance\Aal;
use Padosoft\Iam\Contracts\Assurance\AssuranceProvider;
use Padosoft\Iam\Contracts\Assurance\FactorVerifier;
use Padosoft\Iam\Contracts\Assurance\StepUpProvider;
use Padosoft\Iam\Contracts\Assurance\StepUpPurpose;
use Padosoft\Iam\Contracts\Identity\SessionMeta;
use Padosoft\Iam\Contracts\Identity\SessionRef;
use Padosoft\Iam\Contracts\Identity\SessionRegistry;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Iam\Domain\Identity\Models\Session;
use Padosoft\Iam\Domain\Identity\Models\User;

uses(RefreshDatabase::class);

/** @return array{0: SubjectRef, 1: SessionRef} */
function subjectAndSession(Aal $aal = Aal::AAL1): array
{
    $user = new User;
    $user->forceFill(['email' => 'u@test.local'])->save();
    $subject = new SubjectRef('user', $user->id);
    $session = app(SessionRegistry::class)->start($subject, new SessionMeta(aal: $aal));

    return [$subject, $session];
}

function withPassingFactor(): void
{
    app()->bind(FactorVerifier::class, fn () => new class implements FactorVerifier
    {
        public function verify(SubjectRef $subject, array $payload): bool
        {
            return true;
        }
    });
}

it('currentAal legge l\'AAL dalla sessione attiva', function () {
    [$subject, $session] = subjectAndSession(Aal::AAL2);

    expect(app(AssuranceProvider::class)->currentAal($subject, $session))->toBe(Aal::AAL2);
});

it('currentAal è AAL1 per una sessione revocata (fail-closed)', function () {
    [$subject, $session] = subjectAndSession(Aal::AAL2);
    app(SessionRegistry::class)->revokeSession($session->id, 'logout');

    expect(app(AssuranceProvider::class)->currentAal($subject, $session))->toBe(Aal::AAL1);
});

it('lo step-up con fattore valido eleva la sessione ad AAL2 + step_up_at', function () {
    withPassingFactor();
    [$subject, $session] = subjectAndSession();

    $challenge = app(StepUpProvider::class)->require($subject, new StepUpPurpose('billing.export', Aal::AAL2), $session);
    $result = app(StepUpProvider::class)->verify($challenge->id, ['code' => '123456']);

    expect($result->success)->toBeTrue()
        ->and($result->aal)->toBe(Aal::AAL2)
        ->and(app(AssuranceProvider::class)->currentAal($subject, $session))->toBe(Aal::AAL2);

    $model = Session::query()->whereKey($session->id)->first();
    expect($model->step_up_at)->not->toBeNull();
});

it('lo step-up senza un FactorVerifier configurato fallisce (default fail-closed)', function () {
    [$subject, $session] = subjectAndSession();

    $challenge = app(StepUpProvider::class)->require($subject, new StepUpPurpose('billing.export'), $session);
    $result = app(StepUpProvider::class)->verify($challenge->id, ['code' => 'x']);

    expect($result->success)->toBeFalse()
        ->and(app(AssuranceProvider::class)->currentAal($subject, $session))->toBe(Aal::AAL1);
});

it('una challenge non può essere riusata (single-use)', function () {
    withPassingFactor();
    [$subject, $session] = subjectAndSession();

    $challenge = app(StepUpProvider::class)->require($subject, new StepUpPurpose('billing.export', Aal::AAL2), $session);
    app(StepUpProvider::class)->verify($challenge->id, []);          // primo uso → OK
    $replay = app(StepUpProvider::class)->verify($challenge->id, []); // riuso → fallisce

    expect($replay->success)->toBeFalse();
});

it('una challenge scaduta fallisce', function () {
    withPassingFactor();
    config(['iam.authentication.session.step_up_window' => 60]);
    [$subject, $session] = subjectAndSession();

    $challenge = app(StepUpProvider::class)->require($subject, new StepUpPurpose('billing.export', Aal::AAL2), $session);
    $this->travel(2)->minutes();

    expect(app(StepUpProvider::class)->verify($challenge->id, [])->success)->toBeFalse();
});

it('lo step-up su sessione revocata non eleva', function () {
    withPassingFactor();
    [$subject, $session] = subjectAndSession();
    $challenge = app(StepUpProvider::class)->require($subject, new StepUpPurpose('billing.export', Aal::AAL2), $session);
    app(SessionRegistry::class)->revokeSession($session->id, 'logout');

    expect(app(StepUpProvider::class)->verify($challenge->id, [])->success)->toBeFalse();
});
