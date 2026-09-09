<?php

declare(strict_types=1);

namespace Remediate\Tests\Unit\Solver;

use Composer\DependencyResolver\Request;
use PHPUnit\Framework\TestCase;
use Remediate\Engine\Candidate\Candidate;
use Remediate\Engine\Candidate\Strategy;
use Remediate\Engine\Solver\FallbackSolver;
use Remediate\Engine\Solver\ReleaseAgeGuard;
use Remediate\Engine\Solver\LockDiff;
use Remediate\Engine\Solver\ScratchWorkspace;
use Remediate\Engine\Solver\SolveResult;
use Remediate\Engine\Solver\SolveStatus;
use Remediate\Tests\Support\FakeSolver;
use Remediate\Tests\Support\ScriptedProject;

final class FallbackSolverTest extends TestCase
{
    private function workspace(): ScratchWorkspace
    {
        $dir = sys_get_temp_dir() . '/composer-remediate-fb-' . bin2hex(random_bytes(4));
        mkdir($dir);
        file_put_contents($dir . '/composer.json', '{}');
        file_put_contents($dir . '/composer.lock', '{"packages": [], "packages-dev": []}');
        $workspace = ScratchWorkspace::fromFiles($dir . '/composer.json', $dir . '/composer.lock');
        @unlink($dir . '/composer.json');
        @unlink($dir . '/composer.lock');
        @rmdir($dir);

        return $workspace;
    }

    public function testErrorsAreRetriedConflictsAreNot(): void
    {
        $candidate = new Candidate(Strategy::LockRefresh, ['acme/lib'], Request::UPDATE_ONLY_LISTED, [], false, [], 'x');
        $after = ScriptedProject::lock([['acme/lib', '1.1.0']]);

        $primary = new FakeSolver(new SolveResult(SolveStatus::Error, null, '', 'API mismatch'));
        $fallback = (new FakeSolver())->resolves('composer update acme/lib', $after);
        $solver = new FallbackSolver($primary, $fallback);
        self::assertSame(SolveStatus::Resolved, $solver->solve($candidate, $this->workspace())->status);
        self::assertSame(1, $solver->fallbackCount());
        self::assertStringContainsString('retried via', $solver->describe());

        $conflicting = new FakeSolver();
        $untouched = new FakeSolver();
        $solver = new FallbackSolver($conflicting, $untouched);
        self::assertSame(SolveStatus::Conflict, $solver->solve($candidate, $this->workspace())->status);
        self::assertSame([], $untouched->calls);
    }

    public function testDoubleFailureKeepsBothExplanations(): void
    {
        $candidate = new Candidate(Strategy::LockRefresh, ['acme/lib'], Request::UPDATE_ONLY_LISTED, [], false, [], 'x');
        $solver = new FallbackSolver(new FakeSolver(new SolveResult(SolveStatus::Error, null, '', 'first')), new FakeSolver(new SolveResult(SolveStatus::Error, null, '', 'second')));
        $result = $solver->solve($candidate, $this->workspace());
        self::assertSame(SolveStatus::Error, $result->status);
        self::assertStringContainsString('first', $result->explanation());
        self::assertStringContainsString('second', $result->explanation());
    }

    public function testReleaseAgeGuardCountsUnknownDatesAsTooYoung(): void
    {
        $before = ScriptedProject::lock([['acme/lib', '1.0.0']]);
        $dated = ScriptedProject::lock([['acme/lib', '1.1.0', false, '2020-01-01']]);
        $undated = ScriptedProject::lock([['acme/lib', '1.1.0']]);
        $guard = new ReleaseAgeGuard(7);
        self::assertSame([], $guard->tooYoung(LockDiff::between($before, $dated), $dated));
        self::assertCount(1, $guard->tooYoung(LockDiff::between($before, $undated), $undated));
        self::assertSame([], (new ReleaseAgeGuard(0))->tooYoung(LockDiff::between($before, $undated), $undated), 'no cooldown, no check');
    }
}
