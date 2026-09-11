<?php

declare(strict_types=1);

namespace Remediate\Engine\Plan;

use Remediate\Engine\Candidate\Candidate;
use Remediate\Engine\Solver\LockDiff;
use Remediate\Engine\Solver\SolveResult;

/**
 * One command that addresses several findings at once, verified by a single solve.
 */
final class CombinedRemediation
{
    /**
     * @param list<string> $fixedKeys   finding keys (advisory@package) removed by this command
     * @param list<string> $unfixedKeys finding keys that remain after this command
     */
    public function __construct(
        public readonly Candidate $candidate,
        public readonly SolveResult $result,
        public readonly LockDiff $diff,
        public readonly array $fixedKeys,
        public readonly array $unfixedKeys,
        /** @var list<string> coverage-gap warnings about packages this command adds (accepted gaps only) */
        public readonly array $coverageGaps = [],
    ) {
    }

    public function fixedCount(): int
    {
        return count($this->fixedKeys);
    }

    public function totalCount(): int
    {
        return count($this->fixedKeys) + count($this->unfixedKeys);
    }

    public function fixesAll(): bool
    {
        return $this->unfixedKeys === [];
    }
}
