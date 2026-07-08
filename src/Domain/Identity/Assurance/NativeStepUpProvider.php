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

    /**
     * AAL massimo che il provider NATIVO può realmente attestare: TOTP + passkey (WebAuthn user-verifying)
     * = AAL2. L'AAL3 (autenticatore hardware/PSD2) richiede un adapter dedicato (Rebel/FIDO2 resident key):
     * il provider nativo NON deve mai concederlo (fail-closed).
     */
    private const NATIVE_MAX_AAL = Aal::AAL2;

    public function require(SubjectRef $subject, StepUpPurpose $purpose, SessionRef $session): StepUpChallenge
    {
        // IAM-32: il provider nativo non può soddisfare un AAL3 → rifiuta a monte invece di emettere una
        // challenge che poi eleverebbe falsamente a un livello non raggiunto (un passkey attesta AAL2, non AAL3).
        if ($purpose->requiredAal->rank() > self::NATIVE_MAX_AAL->rank()) {
            throw new \RuntimeException("Step-up AAL {$purpose->requiredAal->value} non supportato dal provider nativo (max ".self::NATIVE_MAX_AAL->value.'): serve un adapter hardware.');
        }

        $expiresAt = Carbon::now()->addSeconds($this->stepUpWindow());
        // IAM-32: il provider nativo cappa a AAL2 e verifica un fattore TOTP (Fortify); il passkey/WebAuthn
        // (con nonce per-challenge, vedi la nota in verify()) è lavoro futuro. Quindi il metodo è 'totp' —
        // niente più ramo `>= AAL3` morto che avrebbe comunque sempre dato 'totp' dopo il cap.
        $method = 'totp';

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

        // IAM-32: cap l'elevazione all'AAL che il provider nativo può davvero attestare (mai oltre AAL2).
        // Difesa in profondità: anche se una challenge AAL3 sfuggisse a require(), non eleviamo a AAL3.
        // NOTA (da fare prima di esporre lo step-up via HTTP): legare il FATTORE verificato al method/AAL
        // richiesto (il FactorVerifier deve ricevere method+required_aal e ritornare l'AAL raggiunto — cambio
        // di contratto breaking) e persistere un nonce WebAuthn per-challenge in require()/verify().
        $target = Aal::fromString($challenge->required_aal);
        if ($target->rank() > self::NATIVE_MAX_AAL->rank()) {
            return new StepUpResult(false, Aal::AAL1);
        }
        $session->recordStepUp($target->value);

        return new StepUpResult(true, $target);
    }

    private function stepUpWindow(): int
    {
        $value = config('iam.authentication.session.step_up_window', 300);

        return is_int($value) && $value > 0 ? $value : 300;
    }
}
