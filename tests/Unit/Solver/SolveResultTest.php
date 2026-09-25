<?php

declare(strict_types=1);

namespace Remediate\Tests\Unit\Solver;

use PHPUnit\Framework\TestCase;
use Remediate\Engine\Solver\SolveResult;
use Remediate\Engine\Solver\SolveStatus;

final class SolveResultTest extends TestCase
{
    public function testTheExplanationLeavesOutGitHubWorkflowCommands(): void
    {
        $output = "Loading composer repositories with package information\n"
            . "Your requirements could not be resolved to an installable set of packages.\n\n"
            . "  Problem 1\n    - acme/lib 2.0.0 requires php >=8.1\n"
            . "::error ::Your requirements could not be resolved to an installable set of packages.%0A%0A  Problem 1\n"
            . "::warning file=composer.json,line=3::something\n";

        self::assertSame(
            "Your requirements could not be resolved to an installable set of packages.\n  Problem 1\n    - acme/lib 2.0.0 requires php >=8.1",
            (new SolveResult(SolveStatus::Conflict, null, $output))->explanation(),
        );
    }
}
