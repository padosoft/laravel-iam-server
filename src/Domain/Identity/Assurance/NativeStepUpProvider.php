<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Identity\Assurance;

use Illuminate\Support\Carbon;
use Padosoft\Iam\Contracts\Assurance\Aal;
use Padosoft\Iam\Contracts\Assurance\FactorVerifier;
use Padosoft\Iam\Contracts\Assurance\StepUpChallenge;
use Padosoft\Iam\Contracts\Assurance\StepUpProvider;
use Padosoft\Iam\Contracts\Assurance\StepUpPurpose;
use Padosoft\Iam\Contracts\Assurance\StepUpResult;
use Padosoft\Iam\Contracts\Identity\SessionRef;
use Padosoft\Iam\Contracts\Identity\SessionRegistry;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Iam\Domain\Identity\Models\Session;
use Padosoft\Iam\Domain\Identity\Models\StepUpChallengeModel;

/**
 * Step-up nativo (doc 10 §4): emette una challenge single-use a scadenza breve; alla verifica
 * (delegata a {@see FactorVerifier} = Fortify/passkeys in M5.4) eleva l'AAL della sessione
 * attiva + step_up_at. Fail-closed: challenge scaduta/consumata o sessione non attiva ⇒ insuccesso.
 */
final class NativeStepUpProvider implements StepUpProvider
{
    public function __construct(
        private readonly FactorVerifier $verifier,
        private readonly SessionRegistry $sessions,
    ) {}

    public function require(SubjectRef $subject, StepUpPurpose $purpose, SessionRef $session): StepUpChallenge
    {
        $expiresAt = Carbon::now()->addSeconds($this->stepUpWindow());
        $method = $purpose->requiredAal->rank() >= Aal::AAL3->rank() ? 'passkey' : 'totp';

        $challenge = StepUpChallengeModel::query()->create([
            'session_id' => $session->id,
            'user_id' => $subject->id,
            'action' => $purpose->action,
            'required_aal' => $purpose->requiredAal->value,
            'method' => $method,
            'expires_at' => $expiresAt,
        ]);

        return new StepUpChallenge($challenge->id, $method, $expiresAt->toDateTimeImmutable());
    }

    public function verify(string $challengeId, array $payload): StepUpResult
    {
        $challenge = $challengeId !== '' ? StepUpChallengeModel::query()->whereKey($challengeId)->first() : null;
        if ($challenge === null || $challenge->consumed_at !== null || Carbon::now()->greaterThan($challenge->expires_at)) {
            return new StepUpResult(false, Aal::AAL1);
        }

        // Fattore prima del consumo: un codice errato NON brucia la challenge (retry possibile).
        $subject = new SubjectRef('user', $challenge->user_id);
        if (!$this->verifier->verify($subject, $payload)) {
            return new StepUpResult(false, Aal::AAL1);
        }

        // Claim ATOMICO single-use: l'UPDATE condizionale consuma la challenge; solo UNA richiesta
        // concorrente ottiene affected=1 → solo quella eleva (chiude la TOCTOU del doppio step-up).
        $now = Carbon::now();
        $claimed = StepUpChallengeModel::query()
            ->whereKey($challenge->id)
            ->whereNull('consumed_at')
            ->where('expires_at', '>', $now)
            ->update(['consumed_at' => $now]);
        if ($claimed !== 1) {
            return new StepUpResult(false, Aal::AAL1);
        }

        // Eleva SOLO se la sessione è ancora attiva.
        $session = Session::query()->whereKey($challenge->session_id)->first();
        if ($session === null || !$this->sessions->active($session->id)) {
            return new StepUpResult(false, Aal::AAL1);
        }

        $target = Aal::fromString($challenge->required_aal);
        $session->recordStepUp($target->value);

        return new StepUpResult(true, $target);
    }

    private function stepUpWindow(): int
    {
        $value = config('iam.authentication.session.step_up_window', 300);

        return is_int($value) && $value > 0 ? $value : 300;
    }
}
