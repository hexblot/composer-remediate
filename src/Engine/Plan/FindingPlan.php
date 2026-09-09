<?php

declare(strict_types=1);

namespace Remediate\Engine\Plan;

use Remediate\Engine\Candidate\Candidate;
use Remediate\Engine\Matching\Finding;

final class FindingPlan
{
    /**
     * @param list<EvaluatedCandidate> $evaluated all candidates in evaluation order
     * @param list<EvaluatedCandidate> $ranked    valid candidates, best first
     * @param list<Candidate>          $skipped   candidates not solved because a better one already existed
     */
    public function __construct(
        public readonly Finding $finding,
        public readonly array $evaluated,
        public readonly array $ranked,
        public readonly ?string $blocker = null,
        public readonly array $skipped = [],
    ) {
    }

    public function recommended(): ?EvaluatedCandidate
    {
        return $this->ranked[0] ?? null;
    }

    public function hasRemediation(): bool
    {
        return $this->ranked !== [];
    }
}
