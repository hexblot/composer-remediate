<?php

declare(strict_types=1);

namespace Remediate\Engine\Plan;

use Remediate\Engine\Candidate\Candidate;
use Remediate\Engine\Matching\Finding;
use Remediate\Engine\Solver\SolveStatus;

final class FindingPlan
{
    /**
     * @param list<EvaluatedCandidate> $evaluated             all candidates in evaluation order
     * @param list<EvaluatedCandidate> $ranked                valid candidates, best first
     * @param list<Candidate>          $skipped               candidates not solved because a better one already existed
     * @param list<Finding>            $related               further advisories on the same package, remediated by the same plan
     * @param SolveStatus|null         $infrastructureFailure set when no candidate could be verified because the tool
     *                                                        (Error) or the network (Transport) failed, as opposed to a
     *                                                        genuine absence of a fix
     * @param bool                     $exhausted             the solver budget ran out before every candidate was tried:
     *                                                        "no fix found" then means "none found within the search"
     * @param int                      $solveCount            solver invocations spent on this finding, probes included
     */
    public function __construct(
        public readonly Finding $finding,
        public readonly array $evaluated,
        public readonly array $ranked,
        public readonly ?string $blocker = null,
        public readonly array $skipped = [],
        public readonly array $related = [],
        public readonly ?SolveStatus $infrastructureFailure = null,
        public readonly bool $exhausted = false,
        public readonly int $solveCount = 0,
    ) {
    }

    /** Whether any advisory of this package is in CISA's Known Exploited Vulnerabilities catalogue. */
    public function isKnownExploited(): bool
    {
        foreach ($this->allFindings() as $finding) {
            if ($finding->advisory->isKnownExploited()) {
                return true;
            }
        }

        return false;
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

    /**
     * Constraint drag: the fix is only reachable by changing a constraint in composer.json. Names the
     * root requirement that blocks it, or null when the recommendation stays within current constraints.
     */
    public function constraintDrag(): ?string
    {
        $recommended = $this->recommended();
        if ($recommended === null || !$recommended->candidate->changesRootConstraints()) {
            return null;
        }
        $parts = [];
        foreach ($recommended->candidate->rootConstraintChanges as $change) {
            $parts[] = sprintf('%s %s', $change->packageName, $change->fromConstraint ?? '(not required)');
        }

        return sprintf('composer.json requires %s, which blocks every fix within the current constraints; the recommendation widens %s to %s.', implode(' and ', $parts), count($parts) === 1 ? 'it' : 'them', implode(', ', array_map(static fn ($c): string => $c->toConstraint, $recommended->candidate->rootConstraintChanges)));
    }

    /** How the absence of a remediation should be read, for reports. */
    public function outcome(): string
    {
        if ($this->hasRemediation()) {
            return 'verified';
        }

        return match (true) {
            $this->infrastructureFailure === SolveStatus::Transport => 'unknown: network failure while solving',
            $this->infrastructureFailure === SolveStatus::Error => 'unknown: solver error',
            $this->exhausted => 'none found within the search budget',
            default => 'none',
        };
    }
}
