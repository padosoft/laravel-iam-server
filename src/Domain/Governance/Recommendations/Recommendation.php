<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Governance\Recommendations;

/**
 * Una raccomandazione di least-privilege/anomaly (doc 14 §7). È SOLO una proposta (draft): il
 * recommender non muta nulla — espone candidati a revoca/trasformazione che un umano valuta
 * ("deterministic first, AI explanation second"). Deterministica e riproducibile dai dati esistenti.
 */
final readonly class Recommendation
{
    /**
     * @param  'unused_grant'|'direct_permission'|'wide_role'|'toxic_combination'|'permanent_privileged'  $type
     * @param  'low'|'medium'|'high'  $severity
     * @param  array<string, mixed>  $evidence
     */
    public function __construct(
        public string $type,
        public string $severity,
        public string $recommendation,
        public string $targetRef,
        public ?string $subject,
        public string $detail,
        public array $evidence = [],
    ) {}

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'type' => $this->type,
            'severity' => $this->severity,
            'recommendation' => $this->recommendation,
            'target_ref' => $this->targetRef,
            'subject' => $this->subject,
            'detail' => $this->detail,
            'evidence' => $this->evidence,
        ];
    }
}
