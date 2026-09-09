<?php

declare(strict_types=1);

namespace Remediate\Engine\Plan;

use Remediate\Engine\Candidate\Candidate;
use Remediate\Engine\Solver\LockDiff;
use Remediate\Engine\Solver\SolveResult;

final class EvaluatedCandidate
{
    public function __construct(
        public readonly Candidate $candidate,
        public readonly SolveResult $result,
        public readonly ?LockDiff $diff,
        public readonly bool $valid,
        public readonly ?string $rejectionReason,
    ) {
    }
}
