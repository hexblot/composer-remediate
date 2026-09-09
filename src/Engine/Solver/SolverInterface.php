<?php

declare(strict_types=1);

namespace Remediate\Engine\Solver;

use Remediate\Engine\Candidate\Candidate;

interface SolverInterface
{
    public function solve(Candidate $candidate, ScratchWorkspace $workspace): SolveResult;

    /** Whether the Composer that will execute the recommendation understands --minimal-changes. */
    public function supportsMinimalChanges(): bool;

    public function describe(): string;
}
