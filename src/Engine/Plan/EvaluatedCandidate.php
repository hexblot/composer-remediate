<?php

declare(strict_types=1);

namespace Remediate\Engine\Plan;

use Remediate\Engine\Candidate\Candidate;
use Remediate\Engine\Solver\LockDiff;
use Remediate\Engine\Solver\SolveResult;

final class EvaluatedCandidate
{
    /**
     * @param list<string> $blockingRisk packages this command changes that still carry another advisory
     *                                   afterwards; Composer 2.10+ advisory blocking may refuse the update
     *                                   until those are addressed or blocking is disabled
     */
    public function __construct(
        public readonly Candidate $candidate,
        public readonly SolveResult $result,
        public readonly ?LockDiff $diff,
        public readonly bool $valid,
        public readonly ?string $rejectionReason,
        public readonly array $blockingRisk = [],
    ) {
    }
}
