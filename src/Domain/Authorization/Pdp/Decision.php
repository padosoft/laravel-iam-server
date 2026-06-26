<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Authorization\Pdp;

/**
 * Esito deterministico del PDP (doc 09 §8). L'explanation è derivata dalla
 * valutazione reale ed è citabile in audit.
 */
final readonly class Decision
{
    /**
     * @param  list<array{type: string, key: string}>  $matched
     * @param  list<string>  $failedConditions
     * @param  list<string>  $explanation
     */
    public function __construct(
        public bool $allowed,
        public string $decisionId,
        public int $policyVersion,
        public bool $requiresStepUp = false,
        public ?string $requiredAal = null,
        public array $matched = [],
        public array $failedConditions = [],
        public array $explanation = [],
    ) {}

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'allowed' => $this->allowed,
            'decision_id' => $this->decisionId,
            'policy_version' => $this->policyVersion,
            'requires_step_up' => $this->requiresStepUp,
            'required_aal' => $this->requiredAal,
            'matched' => $this->matched,
            'failed_conditions' => $this->failedConditions,
            'explanation' => $this->explanation,
        ];
    }
}
