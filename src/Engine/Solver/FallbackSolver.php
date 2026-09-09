<?php

declare(strict_types=1);

namespace Remediate\Engine\Solver;

use Remediate\Engine\Candidate\Candidate;

/**
 * Runs the primary solver and, when it fails for a reason that is not a dependency conflict or a
 * network problem (an exception inside Composer's PHP API, typically an incompatibility), retries the
 * same candidate with the fallback. Conflicts and transport errors are not retried: a second solver
 * would reach the same conclusion.
 */
final class FallbackSolver implements SolverInterface
{
    private int $fallbacks = 0;

    public function __construct(private readonly SolverInterface $primary, private readonly SolverInterface $fallback)
    {
    }

    public function solve(Candidate $candidate, ScratchWorkspace $workspace): SolveResult
    {
        $result = $this->primary->solve($candidate, $workspace);
        if ($result->status !== SolveStatus::Error) {
            return $result;
        }
        ++$this->fallbacks;
        $second = $this->fallback->solve($candidate, $workspace);
        if ($second->status === SolveStatus::Error) {
            return new SolveResult(SolveStatus::Error, null, $result->output . "\n" . $second->output, sprintf('%s; fallback %s also failed: %s', $result->explanation(), $this->fallback->describe(), $second->explanation()), $second->exitCode);
        }

        return $second;
    }

    public function supportsMinimalChanges(): bool
    {
        return $this->primary->supportsMinimalChanges();
    }

    public function describe(): string
    {
        return $this->primary->describe() . ($this->fallbacks > 0 ? sprintf(', %d solve%s retried via %s', $this->fallbacks, $this->fallbacks === 1 ? '' : 's', $this->fallback->describe()) : sprintf(' (fallback: %s)', $this->fallback->describe()));
    }

    public function fallbackCount(): int
    {
        return $this->fallbacks;
    }
}
