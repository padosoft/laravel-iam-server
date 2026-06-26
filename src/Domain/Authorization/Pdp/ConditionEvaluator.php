<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Authorization\Pdp;

/**
 * Valuta le condizioni ABAC di un grant (formato {field: {op: value}}) contro il context.
 * Operatori sconosciuti → fail-closed (condizione non soddisfatta).
 */
final class ConditionEvaluator
{
    /**
     * @param  array<string, mixed>  $conditions
     * @param  array<string, mixed>  $context
     * @return list<string> condizioni fallite (vuoto = tutte passate)
     */
    public function failed(array $conditions, array $context): array
    {
        $failed = [];

        foreach ($conditions as $field => $spec) {
            if (!is_array($spec)) {
                continue;
            }
            /** @var array<string, mixed> $spec */
            foreach ($spec as $op => $expected) {
                $actual = $context[$field] ?? null;
                if (!$this->compare($actual, (string) $op, $expected)) {
                    $failed[] = sprintf(
                        '%s %s %s (actual: %s)',
                        $field,
                        (string) $op,
                        $this->stringify($expected),
                        $this->stringify($actual),
                    );
                }
            }
        }

        return $failed;
    }

    private function compare(mixed $actual, string $op, mixed $expected): bool
    {
        $numeric = is_numeric($actual) && is_numeric($expected);

        return match ($op) {
            '=', '==' => $actual == $expected,
            '!=' => $actual != $expected,
            '<' => $numeric && (float) $actual < (float) $expected,
            '<=' => $numeric && (float) $actual <= (float) $expected,
            '>' => $numeric && (float) $actual > (float) $expected,
            '>=' => $numeric && (float) $actual >= (float) $expected,
            'in' => is_array($expected) && in_array($actual, $expected, true),
            default => false,
        };
    }

    private function stringify(mixed $value): string
    {
        return is_scalar($value) ? (string) $value : json_encode($value, JSON_THROW_ON_ERROR);
    }
}
