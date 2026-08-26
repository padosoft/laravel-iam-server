<?php

declare(strict_types=1);

use Padosoft\Iam\Domain\Authorization\Pdp\ConditionEvaluator;

/**
 * Pins the two properties an AI-grounding provenance policy rests on.
 *
 * The setting: an assistant answers from a retrieved corpus, and some of
 * that corpus is written by people outside the organisation — inbound mail,
 * tickets, scraped pages. A permission that must never be exercised on the
 * strength of a stranger's text can say so as an ordinary ABAC condition:
 *
 *     {"grounding_provenance": {"=": "trusted_internal"}}
 *
 * No new engine, no new column, no `provenance` special case. The generic
 * evaluator already expresses it, and — critically — already has the right
 * failure mode. That is worth a test rather than a comment, because the
 * whole convention is only safe while these two properties hold, and
 * nothing else in the suite asserts them.
 *
 * See docs-site `/guides/ai-grounding-provenance`.
 */
it('denies when the caller does not state the provenance at all', function (): void {
    // THE load-bearing case. A PEP that forgets to pass the field — or an
    // older caller that does not know about it yet — must be denied, not
    // waved through. An absent attribute is not a satisfied one.
    $failed = (new ConditionEvaluator)->failed(
        ['grounding_provenance' => ['=' => 'trusted_internal']],
        ['organization_id' => 'org_1'],
    );

    expect($failed)->toHaveCount(1)
        ->and($failed[0])->toContain('ASSENTE');
});

it('denies when the grounding was externally authored', function (): void {
    $failed = (new ConditionEvaluator)->failed(
        ['grounding_provenance' => ['=' => 'trusted_internal']],
        ['grounding_provenance' => 'untrusted_external'],
    );

    expect($failed)->toHaveCount(1);
});

it('allows when the grounding was internally authored', function (): void {
    $failed = (new ConditionEvaluator)->failed(
        ['grounding_provenance' => ['=' => 'trusted_internal']],
        ['grounding_provenance' => 'trusted_internal'],
    );

    expect($failed)->toBe([]);
});

it('supports an allow-list of acceptable tiers via `in`', function (): void {
    // A policy that tolerates the organisation's own summaries but not a
    // stranger's prose. Worth pinning because `in` uses strict comparison,
    // so a numeric-looking tier would not match loosely.
    $conditions = ['grounding_provenance' => ['in' => ['trusted_internal', 'machine_generated']]];

    expect((new ConditionEvaluator)->failed($conditions, ['grounding_provenance' => 'machine_generated']))->toBe([]);
    expect((new ConditionEvaluator)->failed($conditions, ['grounding_provenance' => 'untrusted_external']))->toHaveCount(1);
});

it('reports the actual tier in the failure so a denial is diagnosable', function (): void {
    // A deny an operator cannot explain is a deny somebody works around.
    $failed = (new ConditionEvaluator)->failed(
        ['grounding_provenance' => ['=' => 'trusted_internal']],
        ['grounding_provenance' => 'untrusted_external'],
    );

    expect($failed[0])->toContain('untrusted_external');
});
