<?php

declare(strict_types=1);

namespace Remediate\Tests\Support;

use Remediate\Engine\Candidate\Candidate;
use Remediate\Engine\Solver\ScratchWorkspace;
use Remediate\Engine\Solver\SolveResult;
use Remediate\Engine\Solver\SolverInterface;

/**
 * Wraps a solver and kills the first forked worker that reaches it, the way the out-of-memory killer
 * would: no result file, no chance to report anything. Exactly one worker dies, so the test covers
 * the mixed case where some packages were planned and some were not.
 *
 * The object is built in the parent, so the pid it remembers is the parent's; anything solving under
 * a different pid is a child.
 */
final class KilledOnceSolver implements SolverInterface
{
    private readonly int $parentPid;

    private readonly string $marker;

    public function __construct(private readonly SolverInterface $inner)
    {
        $this->parentPid = posix_getpid();
        $this->marker = sys_get_temp_dir() . '/remediate-kill-once-' . bin2hex(random_bytes(6));
    }

    public function __destruct()
    {
        @rmdir($this->marker);
    }

    public function supportsMinimalChanges(): bool
    {
        return $this->inner->supportsMinimalChanges();
    }

    public function describe(): string
    {
        return $this->inner->describe();
    }

    public function solve(Candidate $candidate, ScratchWorkspace $workspace): SolveResult
    {
        // A child, and the first one here: die without leaving a result, as a killed worker does.
        if (posix_getpid() !== $this->parentPid && @mkdir($this->marker) === true) {
            posix_kill(posix_getpid(), SIGKILL);
        }

        return $this->inner->solve($candidate, $workspace);
    }
}
