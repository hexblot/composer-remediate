<?php

declare(strict_types=1);

namespace Remediate\Tests\Unit\Engine;

use PHPUnit\Framework\TestCase;
use Remediate\Engine\Candidate\CandidateGenerator;
use Remediate\Engine\Matching\IgnorePolicy;
use Remediate\Engine\Plan\Plan;
use Remediate\Engine\Planner;
use Remediate\Engine\Solver\ReleaseAgeGuard;
use Remediate\Engine\Solver\SolveResult;
use Remediate\Engine\Solver\SolveStatus;
use Remediate\Output\JsonRenderer;
use Remediate\Tests\Support\FakeSolver;
use Remediate\Tests\Support\ScriptedProject;

/**
 * Planner acceptance rules, exercised with a scripted solver so each rule is tested in isolation:
 * the same rules must hold for individual candidates and for the combined command.
 */
final class PlannerTest extends TestCase
{
    /** @var list<ScriptedProject> */
    private array $projects = [];

    protected function tearDown(): void
    {
        foreach ($this->projects as $project) {
            $project->destroy();
        }
    }

    /**
     * @param array<string, string>                                  $require
     * @param list<array{string, string, 2?: bool, 3?: string|null}> $packages
     * @param array<string, string>                                  $requireDev
     */
    private function project(array $require, array $packages, array $requireDev = []): ScriptedProject
    {
        return $this->projects[] = new ScriptedProject($require, $packages, $requireDev);
    }

    public function testUnknownSeverityAlwaysCountsTowardsTheGate(): void
    {
        $project = $this->project(['acme/lib' => '^1.0'], [['acme/lib', '1.0.0']]);
        $solver = (new FakeSolver())->resolves('composer update acme/lib', ScriptedProject::lock([['acme/lib', '1.1.0']]));
        $planner = new Planner(ScriptedProject::advisories([ScriptedProject::advisory('PKSA-1', 'acme/lib', '<1.1.0', 'unknown')]), $solver);
        $plan = $planner->plan($project->context(), $project->workspace());

        self::assertSame(Plan::EXIT_REMEDIATION_AVAILABLE, $plan->exitCode());
        self::assertSame(Plan::EXIT_REMEDIATION_AVAILABLE, $plan->withFailOn('high')->exitCode(), 'a severity the tool does not recognise must not slip under the threshold');
        self::assertSame(Plan::EXIT_REMEDIATION_AVAILABLE, $plan->withFailOn('critical')->exitCode());
    }

    public function testSolverErrorsYieldToolErrorNotNoFix(): void
    {
        $project = $this->project(['acme/lib' => '^1.0'], [['acme/lib', '1.0.0']]);
        $solver = new FakeSolver(new SolveResult(SolveStatus::Error, null, '', 'RuntimeException: boom'));
        $planner = new Planner(ScriptedProject::advisories([ScriptedProject::advisory('PKSA-1', 'acme/lib', '<1.1.0')]), $solver);
        $plan = $planner->plan($project->context(), $project->workspace());

        self::assertSame(Plan::EXIT_ERROR, $plan->exitCode());
        self::assertSame(SolveStatus::Error, $plan->findings[0]->infrastructureFailure);
        self::assertSame('unknown: solver error', $plan->findings[0]->outcome());
        $json = (new JsonRenderer())->toArray($plan);
        self::assertSame('unknown: solver error', $json['findings'][0]['remediation']['outcome']);
    }

    public function testMixedConflictAndTransportFailuresYieldNetworkExit(): void
    {
        $project = $this->project(['acme/lib' => '^1.0'], [['acme/lib', '1.0.0']]);
        $solver = (new FakeSolver())->on("composer update acme/lib -w -m --with 'acme/lib:>=1.1.0'", new SolveResult(SolveStatus::Transport, null, '', 'curl error 6'));
        $planner = new Planner(ScriptedProject::advisories([ScriptedProject::advisory('PKSA-1', 'acme/lib', '<1.1.0')]), $solver);
        $plan = $planner->plan($project->context(), $project->workspace());

        self::assertSame(Plan::EXIT_SOLVER_FAILURE, $plan->exitCode());
        self::assertStringContainsString('not established', (string) $plan->findings[0]->blocker);
    }

    public function testGenuineAbsenceOfFixIsExitTwo(): void
    {
        $project = $this->project(['acme/lib' => '^1.0'], [['acme/lib', '1.0.0']]);
        $planner = new Planner(ScriptedProject::advisories([ScriptedProject::advisory('PKSA-1', 'acme/lib', '<1.1.0')]), new FakeSolver());
        $plan = $planner->plan($project->context(), $project->workspace());

        self::assertSame(Plan::EXIT_NO_REMEDIATION, $plan->exitCode());
        self::assertNull($plan->findings[0]->infrastructureFailure);
        self::assertSame('none', $plan->findings[0]->outcome());
    }

    public function testCombinedCommandHonoursTheReleaseAgeCooldown(): void
    {
        // Two roots, each fixable on its own with an old shared dependency; updating both drags the
        // shared dependency to a release published today.
        $project = $this->project(['acme/a' => '^1.0', 'acme/b' => '^1.0'], [['acme/a', '1.0.0'], ['acme/b', '1.0.0'], ['acme/shared', '1.0.0']]);
        $old = '2020-01-01';
        $today = (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->format('Y-m-d');
        $solver = (new FakeSolver())
            ->resolves('composer update acme/a', ScriptedProject::lock([['acme/a', '1.1.0', false, $old], ['acme/b', '1.0.0', false, $old], ['acme/shared', '1.0.0', false, $old]]))
            ->resolves('composer update acme/b', ScriptedProject::lock([['acme/a', '1.0.0', false, $old], ['acme/b', '1.1.0', false, $old], ['acme/shared', '1.0.0', false, $old]]))
            ->resolves('composer update acme/a acme/b', ScriptedProject::lock([['acme/a', '1.1.0', false, $old], ['acme/b', '1.1.0', false, $old], ['acme/shared', '2.0.0', false, $today]]));
        $advisories = ScriptedProject::advisories([ScriptedProject::advisory('PKSA-A', 'acme/a', '<1.1.0'), ScriptedProject::advisory('PKSA-B', 'acme/b', '<1.1.0')]);

        $unguarded = (new Planner($advisories, $solver))->plan($project->context(), $project->workspace());
        self::assertNotNull($unguarded->combined);
        self::assertTrue($unguarded->combined->fixesAll());

        $guarded = (new Planner($advisories, $solver, new CandidateGenerator(), true, 10, null, null, new ReleaseAgeGuard(7)))->plan($project->context(), $project->workspace());
        self::assertTrue($guarded->findings[0]->hasRemediation());
        self::assertTrue($guarded->findings[1]->hasRemediation());
        self::assertNull($guarded->combined, 'the merged lock installs a release younger than the cooldown and must be refused');
    }

    public function testReleaseAgeGuardRefusesUnknownReleaseDates(): void
    {
        $project = $this->project(['acme/lib' => '^1.0'], [['acme/lib', '1.0.0']]);
        $solver = (new FakeSolver())->resolves('composer update acme/lib', ScriptedProject::lock([['acme/lib', '1.1.0']]));
        $planner = new Planner(ScriptedProject::advisories([ScriptedProject::advisory('PKSA-1', 'acme/lib', '<1.1.0')]), $solver, new CandidateGenerator(), true, 10, null, null, new ReleaseAgeGuard(7));
        $plan = $planner->plan($project->context(), $project->workspace());

        self::assertFalse($plan->findings[0]->hasRemediation());
        self::assertStringContainsString('release date unknown', (string) $plan->findings[0]->evaluated[0]->rejectionReason);
    }

    public function testNoDevKeepsUntouchedDevFindingsOutOfTheIntroducedCheck(): void
    {
        $project = $this->project(['acme/lib' => '^1.0'], [['acme/lib', '1.0.0'], ['acme/devtool', '1.0.0', true]], ['acme/devtool' => '^1.0']);
        $solver = (new FakeSolver())->resolves('composer update acme/lib', ScriptedProject::lock([['acme/lib', '1.1.0'], ['acme/devtool', '1.0.0', true]]));
        $advisories = ScriptedProject::advisories([ScriptedProject::advisory('PKSA-1', 'acme/lib', '<1.1.0'), ScriptedProject::advisory('PKSA-D', 'acme/devtool', '<2.0.0')]);

        $withDev = (new Planner($advisories, $solver))->plan($project->context(), $project->workspace());
        self::assertCount(2, $withDev->findings);
        self::assertTrue($withDev->findings[0]->hasRemediation());

        $noDev = (new Planner($advisories, $solver, new CandidateGenerator(), false))->plan($project->context(), $project->workspace());
        self::assertCount(1, $noDev->findings);
        self::assertTrue($noDev->findings[0]->hasRemediation(), 'the unchanged dev vulnerability is not "newly introduced"');
        self::assertSame('composer update acme/lib', $noDev->findings[0]->recommended()?->candidate->commandLine(true));
    }

    public function testFixedRangeEscapesEveryKnownAdvisoryOnThePackage(): void
    {
        // 1.0 is vulnerable to A, 1.1 is safe, newest 1.2 is vulnerable to B (which does not hit 1.0).
        $project = $this->project(['acme/lib' => '^1.0'], [['acme/lib', '1.0.0']]);
        $solver = (new FakeSolver())
            ->resolves('composer update acme/lib', ScriptedProject::lock([['acme/lib', '1.2.0']]))
            ->resolves("composer update acme/lib -w -m --with 'acme/lib:>=1.1.0,<1.2.0 || >=1.3.0'", ScriptedProject::lock([['acme/lib', '1.1.0']]));
        $advisories = ScriptedProject::advisories([
            ScriptedProject::advisory('PKSA-A', 'acme/lib', '<1.1.0'),
            ScriptedProject::advisory('PKSA-B', 'acme/lib', '>=1.2.0,<1.3.0'),
        ]);
        $plan = (new Planner($advisories, $solver))->plan($project->context(), $project->workspace());

        self::assertCount(1, $plan->findings);
        self::assertTrue($plan->findings[0]->hasRemediation());
        self::assertSame('1.1.0', $plan->findings[0]->recommended()?->result->after?->get('acme/lib')?->getPrettyVersion());
        self::assertContains("composer update acme/lib -w -m --with 'acme/lib:>=1.1.0,<1.2.0 || >=1.3.0'", $solver->calls, 'the --with range must exclude the version affected by the other advisory');
    }

    public function testIgnoredAdvisoriesDoNotShrinkTheFixedRange(): void
    {
        $project = $this->project(['acme/lib' => '^1.0'], [['acme/lib', '1.0.0']]);
        $solver = (new FakeSolver())->resolves('composer update acme/lib', ScriptedProject::lock([['acme/lib', '1.2.0']]));
        $advisories = ScriptedProject::advisories([
            ScriptedProject::advisory('PKSA-A', 'acme/lib', '<1.1.0'),
            ScriptedProject::advisory('PKSA-B', 'acme/lib', '>=1.2.0,<1.3.0'),
        ]);
        $plan = (new Planner($advisories, $solver, new CandidateGenerator(), true, 10, null, IgnorePolicy::none()->withIds(['PKSA-B'])))->plan($project->context(), $project->workspace());

        self::assertTrue($plan->findings[0]->hasRemediation());
        self::assertSame('composer update acme/lib', $plan->findings[0]->recommended()?->candidate->commandLine(true));
    }

    public function testPlatformArgumentsAreCarriedIntoTheRecommendedCommand(): void
    {
        $project = $this->project(['acme/lib' => '^1.0'], [['acme/lib', '1.0.0']]);
        $solver = (new FakeSolver())->resolves('composer update acme/lib --ignore-platform-req=php', ScriptedProject::lock([['acme/lib', '1.1.0']]));
        $planner = new Planner(ScriptedProject::advisories([ScriptedProject::advisory('PKSA-1', 'acme/lib', '<1.1.0')]), $solver, new CandidateGenerator(extraArguments: ['--ignore-platform-req=php']));
        $plan = $planner->plan($project->context(), $project->workspace());

        self::assertSame('composer update acme/lib --ignore-platform-req=php', $plan->findings[0]->recommended()?->candidate->commandLine(true));
        self::assertSame('composer update acme/lib --ignore-platform-req=php', $plan->combined?->candidate->commandLine(true));
    }

    public function testBlockingRiskIsReportedWhenAChangedPackageStaysVulnerable(): void
    {
        // Fixing acme/lib drags acme/other from 1.0 to 1.1; both are affected by PKSA-O (a pre-existing finding).
        $project = $this->project(['acme/lib' => '^1.0', 'acme/other' => '^1.0'], [['acme/lib', '1.0.0'], ['acme/other', '1.0.0']]);
        $solver = (new FakeSolver())->resolves('composer update acme/lib', ScriptedProject::lock([['acme/lib', '1.1.0'], ['acme/other', '1.1.0']]));
        $advisories = ScriptedProject::advisories([ScriptedProject::advisory('PKSA-1', 'acme/lib', '<1.1.0'), ScriptedProject::advisory('PKSA-O', 'acme/other', '<2.0.0')]);
        $plan = (new Planner($advisories, $solver))->plan($project->context(), $project->workspace());

        self::assertSame(['acme/other'], $plan->findings[0]->recommended()?->blockingRisk);
        self::assertNotEmpty(array_filter($plan->warnings, static fn (string $w): bool => str_contains($w, 'advisory blocking')));
    }

    public function testSolveBudgetBoundsEveryPhaseAndIsReported(): void
    {
        $project = $this->project(['acme/lib' => '^1.0'], [['acme/lib', '1.0.0']]);
        $solver = new FakeSolver();
        $planner = new Planner(ScriptedProject::advisories([ScriptedProject::advisory('PKSA-1', 'acme/lib', '<1.1.0')]), $solver, new CandidateGenerator(), true, 10, null, null, null, 1);
        $plan = $planner->plan($project->context(), $project->workspace());

        self::assertCount(1, $solver->calls);
        self::assertSame(1, $plan->findings[0]->solveCount);
        self::assertTrue($plan->findings[0]->exhausted);
        self::assertSame('none found within the search budget', $plan->findings[0]->outcome());
        self::assertSame('1', $plan->metadata['solver_runs']);
        self::assertNotEmpty($plan->findings[0]->skipped, 'candidates not tried because the budget ran out are listed');
    }

    public function testIncompleteAdvisorySourceIsFlagged(): void
    {
        $project = $this->project(['acme/lib' => '^1.0'], [['acme/lib', '1.0.0']]);
        $planner = new Planner(ScriptedProject::advisories([ScriptedProject::advisory('PKSA-1', 'acme/lib', '<1.1.0')], false), new FakeSolver());
        $plan = $planner->plan($project->context(), $project->workspace());

        self::assertNotEmpty(array_filter($plan->warnings, static fn (string $w): bool => str_contains($w, 'only knows advisories for the current lock')));
    }
}
