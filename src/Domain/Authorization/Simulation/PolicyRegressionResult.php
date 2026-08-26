<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Authorization\Simulation;

/**
 * Esito di una passata di regressione.
 *
 * `skipped` è riportato accanto a `checked` di proposito: un corpus di mille
 * sonde di cui tre portano un'aspettativa è un corpus che protegge tre casi, e
 * un risultato che mostrasse solo "0 fallimenti" lo nasconderebbe.
 */
final readonly class PolicyRegressionResult
{
    /**
     * @param  list<array{subject: string, permission: string, resource: string|null, expected_allowed: bool|null, actual_allowed: bool, explanation: list<string>, id: string, source: string, label: string|null, organization_id: string|null, application_key: string|null, decision_id: string, policy_version: int}>  $failures
     */
    public function __construct(
        public int $checked,
        public int $skipped,
        public array $failures,
    ) {}

    public function passed(): bool
    {
        return $this->failures === [];
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'passed' => $this->passed(),
            'checked' => $this->checked,
            'skipped_without_expectation' => $this->skipped,
            'failures' => $this->failures,
        ];
    }
}
