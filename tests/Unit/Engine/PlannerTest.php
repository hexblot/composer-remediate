<?php

declare(strict_types=1);

namespace Remediate\Tests\Unit\Engine;

use PHPUnit\Framework\TestCase;
use Remediate\Engine\Candidate\CandidateGenerator;
use Remediate\Engine\Matching\IgnorePolicy;
use Remediate\Engine\Plan\CombinedOutcome;
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
     * @param array<string, string>                                                        $require
     * @param list<array{string, string, 2?: bool, 3?: string|null, 4?: bool|string|null}> $packages
     * @param array<string, string>                                                        $requireDev
     * @param array<string, array<string, string>>                                         $requires
     */
    private function project(array $require, array $packages, array $requireDev = [], array $requires = []): ScriptedProject
    {
        return $this->projects[] = new ScriptedProject($require, $packages, $requireDev, $requires);
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

    public function testGlobalSearchSwapsInALowerRankedCandidateWhenTheMergedWinnersDoNotResolve(): void
    {
        $project = $this->project(['acme/a' => '^1.0', 'acme/b' => '^1.0'], [['acme/a', '1.0.0'], ['acme/b', '1.0.0']]);
        $solver = (new FakeSolver())
            ->resolves('composer update acme/a', ScriptedProject::lock([['acme/a', '1.1.0'], ['acme/b', '1.0.0']]))
            ->resolves('composer update acme/b', ScriptedProject::lock([['acme/a', '1.0.0'], ['acme/b', '1.1.0']]))
            ->resolves("composer update acme/b -w -m --with 'acme/b:>=1.1.0'", ScriptedProject::lock([['acme/a', '1.0.0'], ['acme/b', '1.1.0']]))
            ->on('composer update acme/a acme/b', new SolveResult(SolveStatus::Conflict, null, '', "Your requirements could not be resolved to an installable set of packages.\n  - acme/b 1.1.0 conflicts with acme/a 1.1.0"))
            ->resolves("composer update acme/a acme/b -w -m --with 'acme/b:>=1.1.0'", ScriptedProject::lock([['acme/a', '1.1.0'], ['acme/b', '1.1.0']]));
        $advisories = ScriptedProject::advisories([ScriptedProject::advisory('PKSA-A', 'acme/a', '<1.1.0'), ScriptedProject::advisory('PKSA-B', 'acme/b', '<1.1.0')]);

        $plan = (new Planner($advisories, $solver))->plan($project->context(), $project->workspace());

        self::assertNotNull($plan->combined);
        self::assertTrue($plan->combined->fixesAll());
        self::assertSame("composer update acme/a acme/b -w -m --with 'acme/b:>=1.1.0'", $plan->combined->candidate->commandLine());
        self::assertCount(2, $plan->combinedAttempts);
        self::assertSame(CombinedOutcome::Unresolved, $plan->combinedAttempts[0]->outcome);
        self::assertStringContainsString('acme/b 1.1.0 conflicts', (string) $plan->combinedAttempts[0]->reason);
        self::assertFalse($plan->combinedAttempts[0]->chosen);
        self::assertSame(CombinedOutcome::Accepted, $plan->combinedAttempts[1]->outcome);
        self::assertTrue($plan->combinedAttempts[1]->chosen);
        self::assertSame('acme/b: candidate ranked 2 instead of 1', $plan->combinedAttempts[1]->note);
        self::assertNotContains("composer update acme/a acme/b -w -m --with 'acme/a:>=1.1.0'", $solver->calls, 'the solver named acme/b, so acme/a is not the one to swap');
    }

    public function testGlobalSearchRepairsAMergeThatUndoesOneFindingsFix(): void
    {
        // Updating both roots at once leaves acme/b at its vulnerable version; the second-ranked
        // candidate for acme/b carries a --with constraint that holds.
        $project = $this->project(['acme/a' => '^1.0', 'acme/b' => '^1.0'], [['acme/a', '1.0.0'], ['acme/b', '1.0.0']]);
        $solver = (new FakeSolver())
            ->resolves('composer update acme/a', ScriptedProject::lock([['acme/a', '1.1.0'], ['acme/b', '1.0.0']]))
            ->resolves('composer update acme/b', ScriptedProject::lock([['acme/a', '1.0.0'], ['acme/b', '1.1.0']]))
            ->resolves("composer update acme/b -w -m --with 'acme/b:>=1.1.0'", ScriptedProject::lock([['acme/a', '1.0.0'], ['acme/b', '1.1.0']]))
            ->resolves('composer update acme/a acme/b', ScriptedProject::lock([['acme/a', '1.1.0'], ['acme/b', '1.0.0']]))
            ->resolves("composer update acme/a acme/b -w -m --with 'acme/b:>=1.1.0'", ScriptedProject::lock([['acme/a', '1.1.0'], ['acme/b', '1.1.0']]));
        $advisories = ScriptedProject::advisories([ScriptedProject::advisory('PKSA-A', 'acme/a', '<1.1.0'), ScriptedProject::advisory('PKSA-B', 'acme/b', '<1.1.0')]);

        $plan = (new Planner($advisories, $solver))->plan($project->context(), $project->workspace());

        self::assertNotNull($plan->combined);
        self::assertTrue($plan->combined->fixesAll());
        self::assertSame(CombinedOutcome::Partial, $plan->combinedAttempts[0]->outcome);
        self::assertSame(1, $plan->combinedAttempts[0]->fixed);
        self::assertSame(2, $plan->combinedAttempts[0]->total);
        self::assertSame('leaves PKSA-B@acme/b', $plan->combinedAttempts[0]->reason);
        self::assertSame(CombinedOutcome::Accepted, $plan->combinedAttempts[1]->outcome);
        self::assertTrue($plan->combinedAttempts[1]->chosen);
    }

    public function testGlobalSearchDropsAContributionASiblingsFixAlreadyCovers(): void
    {
        // acme/a requires acme/b; updating acme/a moves acme/b past its advisory, so the command for
        // acme/b is redundant and the smaller command is recommended.
        $project = $this->project(['acme/a' => '^1.0', 'acme/b' => '^1.0'], [['acme/a', '1.0.0'], ['acme/b', '1.0.0']], [], ['acme/a' => ['acme/b' => '^1.0']]);
        $fixed = ScriptedProject::lock([['acme/a', '1.1.0'], ['acme/b', '1.1.0']]);
        $solver = (new FakeSolver())
            ->resolves('composer update acme/a', $fixed)
            ->resolves('composer update acme/b', ScriptedProject::lock([['acme/a', '1.0.0'], ['acme/b', '1.1.0']]))
            ->resolves('composer update acme/a acme/b', $fixed);
        $advisories = ScriptedProject::advisories([ScriptedProject::advisory('PKSA-A', 'acme/a', '<1.1.0'), ScriptedProject::advisory('PKSA-B', 'acme/b', '<1.1.0')]);

        $plan = (new Planner($advisories, $solver))->plan($project->context(), $project->workspace());

        self::assertNotNull($plan->combined);
        self::assertTrue($plan->combined->fixesAll());
        self::assertSame('composer update acme/a', $plan->combined->candidate->commandLine());
        self::assertCount(2, $plan->combinedAttempts);
        self::assertSame(CombinedOutcome::Accepted, $plan->combinedAttempts[0]->outcome);
        self::assertFalse($plan->combinedAttempts[0]->chosen, 'the merged command fixes all but a smaller one exists');
        self::assertSame('without the command for acme/b', $plan->combinedAttempts[1]->note);
        self::assertTrue($plan->combinedAttempts[1]->chosen);
        self::assertNotContains('composer update acme/b', array_slice($solver->calls, -1), 'dropping acme/a is not tried: nothing else moves acme/a');
    }

    public function testGlobalSearchKeepsTheBestPartialResultWhenNoCombinationFixesEverything(): void
    {
        $project = $this->project(['acme/a' => '^1.0', 'acme/b' => '^1.0'], [['acme/a', '1.0.0'], ['acme/b', '1.0.0']]);
        $solver = (new FakeSolver())
            ->resolves('composer update acme/a', ScriptedProject::lock([['acme/a', '1.1.0'], ['acme/b', '1.0.0']]))
            ->resolves("composer update acme/a -w -m --with 'acme/a:>=1.1.0'", ScriptedProject::lock([['acme/a', '1.1.0'], ['acme/b', '1.0.0']]))
            ->resolves('composer update acme/b', ScriptedProject::lock([['acme/a', '1.0.0'], ['acme/b', '1.1.0']]))
            ->resolves("composer update acme/b -w -m --with 'acme/b:>=1.1.0'", ScriptedProject::lock([['acme/a', '1.0.0'], ['acme/b', '1.1.0']]))
            ->resolves('composer update acme/a acme/b', ScriptedProject::lock([['acme/a', '1.1.0'], ['acme/b', '1.0.0']]));
        $advisories = ScriptedProject::advisories([ScriptedProject::advisory('PKSA-A', 'acme/a', '<1.1.0'), ScriptedProject::advisory('PKSA-B', 'acme/b', '<1.1.0')]);

        $plan = (new Planner($advisories, $solver))->plan($project->context(), $project->workspace());

        self::assertNotNull($plan->combined, 'a partial combination is better than none');
        self::assertFalse($plan->combined->fixesAll());
        self::assertSame(1, $plan->combined->fixedCount());
        self::assertSame('composer update acme/a acme/b', $plan->combined->candidate->commandLine());
        self::assertTrue($plan->combinedAttempts[0]->chosen);
        self::assertSame(CombinedOutcome::Unresolved, $plan->combinedAttempts[1]->outcome);
        self::assertStringStartsWith('acme/b: candidate ranked 2 instead of 1', $plan->combinedAttempts[1]->note, 'the unfixed finding is the one swapped first');
        self::assertGreaterThanOrEqual(2, count($plan->combinedAttempts));
        self::assertLessThanOrEqual(1 + Planner::GLOBAL_SOLVE_BUDGET, count($plan->combinedAttempts));
    }

    /**
     * A scripted provider that also knows which packages it could not read records about.
     *
     * @param array<string, string> $gapsByPackage package => gap description
     */
    private static function coverageAware(\Remediate\Engine\Advisory\AdvisoryProvider $inner, array $gapsByPackage): \Remediate\Engine\Advisory\AdvisoryProvider
    {
        return new class($inner, $gapsByPackage) implements \Remediate\Engine\Advisory\AdvisoryProvider, \Remediate\Engine\Advisory\CoverageAware {
            /** @param array<string, string> $gaps */
            public function __construct(private readonly \Remediate\Engine\Advisory\AdvisoryProvider $inner, private readonly array $gaps)
            {
            }

            public function advisoriesFor(array $packageNames): array
            {
                return $this->inner->advisoriesFor($packageNames);
            }

            public function describe(): string
            {
                return $this->inner->describe();
            }

            public function isComplete(): bool
            {
                return true;
            }

            public function coverageWarnings(array $packageNames): array
            {
                return array_values(array_map(static fn (string $g): string => 'Coverage gap: ' . $g, array_intersect_key($this->gaps, array_flip($packageNames))));
            }
        };
    }

    public function testAFixThatAddsAPackageWithUnreadableAdvisoryRecordsIsRejectedUnlessGapsAreAccepted(): void
    {
        // The fix for acme/lib pulls in acme/new, about which the source holds a record it could not read.
        $project = $this->project(['acme/lib' => '^1.0'], [['acme/lib', '1.0.0']]);
        $solver = (new FakeSolver())->resolves('composer update acme/lib', ScriptedProject::lock([['acme/lib', '1.1.0'], ['acme/new', '2.0.0']]));
        $advisories = self::coverageAware(ScriptedProject::advisories([ScriptedProject::advisory('PKSA-1', 'acme/lib', '<1.1.0')]), ['acme/new' => 'Upstream record GHSA-x for acme/new could not be interpreted']);

        $strict = (new Planner($advisories, $solver))->plan($project->context(), $project->workspace());
        self::assertFalse($strict->findings[0]->hasRemediation(), 'the new package cannot be vouched for');
        self::assertStringContainsString('adds packages whose advisory records the source could not read', $strict->findings[0]->evaluated[0]->rejectionReason ?? '');
        self::assertStringContainsString('--accept-coverage-gaps', $strict->findings[0]->evaluated[0]->rejectionReason ?? '');
        self::assertSame([], $strict->coverageGaps, 'the lock itself has no gaps');

        $accepting = (new Planner($advisories, $solver, new CandidateGenerator(), true, 10, null, null, null, Planner::DEFAULT_SOLVE_BUDGET, true))->plan($project->context(), $project->workspace());
        self::assertTrue($accepting->findings[0]->hasRemediation());
        $recommended = $accepting->findings[0]->recommended();
        self::assertNotNull($recommended);
        self::assertSame(['Coverage gap: Upstream record GHSA-x for acme/new could not be interpreted'], $recommended->coverageGaps, 'disclosed on the recommendation');
        self::assertSame($recommended->coverageGaps, $accepting->coverageGaps, 'and at plan level');
        self::assertNotNull($accepting->combined);
        self::assertSame($recommended->coverageGaps, $accepting->combined->coverageGaps);
    }

    public function testACombinedCommandThatFixesEverythingCountsForTheExitCode(): void
    {
        // acme/child has no fix of its own (every candidate conflicts) but updating acme/parent removes it.
        $project = $this->project(['acme/parent' => '^1.0'], [['acme/parent', '1.0.0'], ['acme/child', '1.0.0']], [], ['acme/parent' => ['acme/child' => '^1.0']]);
        $solver = (new FakeSolver())->resolves('composer update acme/parent', ScriptedProject::lock([['acme/parent', '1.1.0'], ['acme/child', '1.1.0']]));
        $advisories = ScriptedProject::advisories([ScriptedProject::advisory('PKSA-P', 'acme/parent', '<1.1.0'), ScriptedProject::advisory('PKSA-C', 'acme/child', '<1.1.0')]);

        $plan = (new Planner($advisories, $solver))->plan($project->context(), $project->workspace());

        $child = array_values(array_filter($plan->findings, static fn ($p): bool => $p->finding->packageName === 'acme/child'))[0];
        self::assertFalse($child->hasRemediation(), 'no standalone fix for the child');
        self::assertNotNull($plan->combined);
        self::assertTrue($plan->combined->fixesAll());
        self::assertSame(Plan::EXIT_REMEDIATION_AVAILABLE, $plan->exitCode(), 'a verified command that fixes everything exists');
    }

    public function testTheCombinedCommandCountsPerGatedFindingUnderFailOnAndBaselines(): void
    {
        // The high-severity parent's update removes its high-severity child; an unrelated low-severity
        // package has no fix at all, so the combined command fixes two of three findings.
        $project = $this->project(['acme/parent' => '^1.0', 'acme/low' => '^1.0'], [['acme/parent', '1.0.0'], ['acme/child', '1.0.0'], ['acme/low', '1.0.0']], [], ['acme/parent' => ['acme/child' => '^1.0']]);
        $solver = (new FakeSolver())->resolves('composer update acme/parent', ScriptedProject::lock([['acme/parent', '1.1.0'], ['acme/child', '1.1.0'], ['acme/low', '1.0.0']]));
        $advisories = ScriptedProject::advisories([
            ScriptedProject::advisory('PKSA-P', 'acme/parent', '<1.1.0', 'high'),
            ScriptedProject::advisory('PKSA-C', 'acme/child', '<1.1.0', 'high'),
            ScriptedProject::advisory('PKSA-L', 'acme/low', '<1.1.0', 'low'),
        ]);

        $plan = (new Planner($advisories, $solver))->plan($project->context(), $project->workspace());

        self::assertNotNull($plan->combined);
        self::assertFalse($plan->combined->fixesAll());
        self::assertSame(Plan::EXIT_NO_REMEDIATION, $plan->exitCode(), 'ungated: the low finding has no fix');
        self::assertSame(Plan::EXIT_REMEDIATION_AVAILABLE, $plan->withFailOn('high')->exitCode(), 'every gated finding is fixed, by the combined command');
        self::assertSame(Plan::EXIT_REMEDIATION_AVAILABLE, $plan->withBaseline(['PKSA-L@acme/low'])->exitCode(), 'the same with the low finding baselined');
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

    public function testAdvisoriesTheAnalysedProjectSuppressesAreNamedInTheReport(): void
    {
        $project = $this->project(['acme/lib' => '^1.0'], [['acme/lib', '1.0.0']]);
        $advisories = ScriptedProject::advisories([ScriptedProject::advisory('PKSA-1', 'acme/lib', '<1.1.0')]);
        $policy = new \Remediate\Engine\Matching\IgnorePolicy(['pksa-1' => true], [], ['pksa-1' => true]);

        $plan = (new Planner($advisories, new FakeSolver(), new CandidateGenerator(), true, 10, null, $policy))->plan($project->context(), $project->workspace());

        self::assertSame([], $plan->findings);
        self::assertStringContainsString("The analysed project's composer.json suppresses advisories", $plan->warnings[0]);
        self::assertStringContainsString('pksa-1', $plan->warnings[0]);
        self::assertStringContainsString("not yours", $plan->warnings[0]);

        // The operator's own --ignore is not reported that way.
        $operator = (new Planner($advisories, new FakeSolver(), new CandidateGenerator(), true, 10, null, IgnorePolicy::none()->withIds(['PKSA-1'])))->plan($project->context(), $project->workspace());
        self::assertStringNotContainsString('suppresses advisories', implode("\n", $operator->warnings));
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

    public function testFindingsAreOrderedByUrgencyKnownExploitedFirstThenEpssThenSeverity(): void
    {
        $project = $this->project(['acme/a' => '^1.0', 'acme/b' => '^1.0', 'acme/c' => '^1.0', 'acme/d' => '^1.0'], [['acme/a', '1.0.0'], ['acme/b', '1.0.0'], ['acme/c', '1.0.0'], ['acme/d', '1.0.0']]);
        $advisories = ScriptedProject::advisories([
            ScriptedProject::advisory('A-1', 'acme/a', '<1.1', 'critical'),                                  // severity only
            ScriptedProject::advisory('B-1', 'acme/b', '<1.1', 'low', 'CVE-2026-2', 0.2),                    // scored, low severity
            ScriptedProject::advisory('C-1', 'acme/c', '<1.1', 'medium', 'CVE-2026-3', 0.05, '2026-01-01'),  // known exploited
            ScriptedProject::advisory('D-1', 'acme/d', '<1.1', 'high', 'CVE-2026-4', 0.9),                   // highest probability, not in KEV
        ]);
        $plan = (new Planner($advisories, new FakeSolver()))->plan($project->context(), $project->workspace());
        self::assertSame(['acme/c', 'acme/d', 'acme/b', 'acme/a'], array_map(static fn ($p): string => $p->finding->packageName, $plan->findings), 'KEV first, then by EPSS, unscored last');
        self::assertTrue($plan->findings[0]->isKnownExploited());
        self::assertSame(1, json_decode((new JsonRenderer())->render($plan), true)['summary']['packages_known_exploited'] ?? null);
    }

    public function testAPackagesUrgencyIsThatOfItsMostUrgentAdvisory(): void
    {
        $project = $this->project(['acme/a' => '^1.0', 'acme/b' => '^1.0'], [['acme/a', '1.0.0'], ['acme/b', '1.0.0']]);
        $advisories = ScriptedProject::advisories([
            ScriptedProject::advisory('A-1', 'acme/a', '<1.1', 'critical', 'CVE-2026-1', 0.5),
            ScriptedProject::advisory('B-1', 'acme/b', '<1.1', 'low'),
            ScriptedProject::advisory('B-2', 'acme/b', '<1.2', 'low', 'CVE-2026-9', 0.01, '2026-03-01'),
        ]);
        $plan = (new Planner($advisories, new FakeSolver()))->plan($project->context(), $project->workspace());
        self::assertSame(['acme/b', 'acme/a'], array_map(static fn ($p): string => $p->finding->packageName, $plan->findings), 'one KEV-listed advisory lifts the whole package');
        self::assertSame(['B-1', 'B-2'], array_map(static fn ($f): string => $f->advisory->id, $plan->findings[0]->allFindings()), 'advisories within the package keep their id order');
    }

    public function testDevelopmentFindingsStayAfterProductionOnesWhateverTheirUrgency(): void
    {
        $project = $this->project(['acme/a' => '^1.0'], [['acme/a', '1.0.0'], ['acme/dev', '1.0.0', true]], ['acme/dev' => '^1.0']);
        $advisories = ScriptedProject::advisories([
            ScriptedProject::advisory('A-1', 'acme/a', '<1.1', 'low'),
            ScriptedProject::advisory('DEV-1', 'acme/dev', '<1.1', 'critical', 'CVE-2026-5', 0.99, '2026-01-01'),
        ]);
        $plan = (new Planner($advisories, new FakeSolver()))->plan($project->context(), $project->workspace());
        self::assertSame(['acme/a', 'acme/dev'], array_map(static fn ($p): string => $p->finding->packageName, $plan->findings));
    }

    public function testAbandonedPackagesOnThePathAndTheVulnerablePackageItselfAreFlagged(): void
    {
        // root -> acme/parent (abandoned, replacement acme/parent-next) -> acme/lib (abandoned, no replacement); acme/free is fine.
        $project = $this->project(
            ['acme/parent' => '^1.0', 'acme/free' => '^1.0'],
            [['acme/parent', '1.0.0', false, null, 'acme/parent-next'], ['acme/lib', '1.0.0', false, null, true], ['acme/free', '1.0.0']],
            [],
            ['acme/parent' => ['acme/lib' => '^1.0']],
        );
        $advisories = ScriptedProject::advisories([
            ScriptedProject::advisory('L-1', 'acme/lib', '<1.1'),
            ScriptedProject::advisory('F-1', 'acme/free', '<1.1'),
        ]);
        $plan = (new Planner($advisories, new FakeSolver()))->plan($project->context(), $project->workspace());
        $byPackage = [];
        foreach ($plan->findings as $fp) {
            $byPackage[$fp->finding->packageName] = $fp->finding;
        }
        self::assertSame(['acme/lib' => null, 'acme/parent' => 'acme/parent-next'], $byPackage['acme/lib']->abandoned);
        self::assertTrue($byPackage['acme/lib']->isAbandoned());
        self::assertSame([], $byPackage['acme/free']->abandoned);
        $json = json_decode((new JsonRenderer())->render($plan), true);
        self::assertSame(1, $json['summary']['packages_with_abandoned_dependency'] ?? null);
        self::assertStringContainsString('Abandoned:', (new \Remediate\Output\TextRenderer())->render($plan));
    }

    public function testIncompleteAdvisorySourceIsFlagged(): void
    {
        $project = $this->project(['acme/lib' => '^1.0'], [['acme/lib', '1.0.0']]);
        $planner = new Planner(ScriptedProject::advisories([ScriptedProject::advisory('PKSA-1', 'acme/lib', '<1.1.0')], false), new FakeSolver());
        $plan = $planner->plan($project->context(), $project->workspace());

        self::assertNotEmpty(array_filter($plan->warnings, static fn (string $w): bool => str_contains($w, 'only knows advisories for the current lock')));
        self::assertCount(1, $plan->findings, 'the finding itself is real and reported');
        self::assertFalse($plan->findings[0]->hasRemediation(), 'but no candidate can be verified against a source that cannot vouch for a candidate lock');
        self::assertSame([], $plan->findings[0]->evaluated, 'nothing was even solved');
        self::assertStringContainsString('no remediation can be verified', (string) $plan->findings[0]->blocker);
        self::assertNull($plan->combined);
        self::assertSame(Plan::EXIT_NO_REMEDIATION, $plan->exitCode(), 'fail closed: a gate sees an unfixed vulnerability, not a verified fix');
    }
}
