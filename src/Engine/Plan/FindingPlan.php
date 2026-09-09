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
     * @param list<Finding>            $related   further advisories on the same package, remediated by the same plan
     */
    public function __construct(
        public readonly Finding $finding,
        public readonly array $evaluated,
        public readonly array $ranked,
        public readonly ?string $blocker = null,
        public readonly array $skipped = [],
        public readonly array $related = [],
    ) {
    }

    /** @return list<Finding> the primary finding followed by the related ones */
    public function allFindings(): array
    {
        return [$this->finding, ...$this->related];
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
