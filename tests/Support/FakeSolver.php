<?php

declare(strict_types=1);

namespace Remediate\Tests\Support;

use Remediate\Engine\Candidate\Candidate;
use Remediate\Engine\Lock\LockSnapshot;
use Remediate\Engine\Solver\ScratchWorkspace;
use Remediate\Engine\Solver\SolveResult;
use Remediate\Engine\Solver\SolverInterface;
use Remediate\Engine\Solver\SolveStatus;

/**
 * Scripted solver for planner tests: results are looked up by the rendered command line (with -m),
 * so a test states "this command yields this lock" without running Composer.
 */
final class FakeSolver implements SolverInterface
{
    /** @var array<string, SolveResult> */
    private array $scripted = [];

    private SolveResult $default;

    /** @var list<string> */
    public array $calls = [];

    public function __construct(?SolveResult $default = null)
    {
        $this->default = $default ?? new SolveResult(SolveStatus::Conflict, null, "Your requirements could not be resolved to an installable set of packages.\n  - scripted conflict");
    }

    public function on(string $commandLine, SolveResult $result): self
    {
        $this->scripted[$commandLine] = $result;

        return $this;
    }

    public function resolves(string $commandLine, LockSnapshot $after): self
    {
        return $this->on($commandLine, new SolveResult(SolveStatus::Resolved, $after, ''));
    }

    public function solve(Candidate $candidate, ScratchWorkspace $workspace): SolveResult
    {
        $command = $candidate->commandLine(true);
        $this->calls[] = $command;

        return $this->scripted[$command] ?? $this->default;
    }

    public function supportsMinimalChanges(): bool
    {
        return true;
    }

    public function describe(): string
    {
        return 'fake solver';
    }
}
