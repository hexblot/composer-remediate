<?php

declare(strict_types=1);

namespace Remediate\Tests\Unit\Engine;

use PHPUnit\Framework\TestCase;
use Remediate\Engine\Parallel\ForkPool;
use Remediate\Engine\Planner;
use Remediate\Output\JsonRenderer;
use Remediate\Tests\Support\FakeSolver;
use Remediate\Tests\Support\ScriptedProject;

/**
 * Planning several packages at once must change how long a run takes and nothing else. These tests
 * hold the parallel path to the sequential one's result, and pin the cases where it declines to fan
 * out: they have to be reported, because a flag that silently did nothing would be worse than one
 * that refused.
 */
final class ParallelPlanningTest extends TestCase
{
    /** @var list<ScriptedProject> */
    private array $projects = [];

    protected function setUp(): void
    {
        $reason = ForkPool::unavailableReason();
        if ($reason !== null) {
            self::markTestSkipped($reason);
        }
    }

    protected function tearDown(): void
    {
        foreach ($this->projects as $project) {
            $project->destroy();
        }
        $this->projects = [];
    }

    private function project(): ScriptedProject
    {
        return $this->projects[] = new ScriptedProject(
            ['acme/a' => '^1.0', 'acme/b' => '^1.0', 'acme/c' => '^1.0'],
            [['acme/a', '1.0.0'], ['acme/b', '1.0.0'], ['acme/c', '1.0.0']],
        );
    }

    private function solver(): FakeSolver
    {
        return (new FakeSolver())
            ->resolves('composer update acme/a', ScriptedProject::lock([['acme/a', '1.1.0'], ['acme/b', '1.0.0'], ['acme/c', '1.0.0']]))
            ->resolves('composer update acme/b', ScriptedProject::lock([['acme/a', '1.0.0'], ['acme/b', '1.1.0'], ['acme/c', '1.0.0']]))
            ->resolves('composer update acme/c', ScriptedProject::lock([['acme/a', '1.0.0'], ['acme/b', '1.0.0'], ['acme/c', '1.1.0']]));
    }

    /** @return list<\Remediate\Engine\Advisory\Advisory> */
    private static function advisoryList(): array
    {
        return [
            ScriptedProject::advisory('PKSA-A', 'acme/a', '<1.1.0'),
            ScriptedProject::advisory('PKSA-B', 'acme/b', '<1.1.0'),
            ScriptedProject::advisory('PKSA-C', 'acme/c', '<1.1.0'),
        ];
    }

    private function plan(int $parallelism): \Remediate\Engine\Plan\Plan
    {
        $project = $this->project();
        $planner = new Planner(
            ScriptedProject::advisories(self::advisoryList(), true, true),
            $this->solver(),
            parallelism: $parallelism,
        );

        return $planner->plan($project->context(), $project->workspace());
    }

    public function testAParallelRunProducesTheSameReportAsASequentialOne(): void
    {
        $sequential = (new JsonRenderer())->toArray($this->plan(1));
        $parallel = (new JsonRenderer())->toArray($this->plan(3));

        // The run is described by where it ran and when, which differ by construction.
        foreach (['analysis_timestamp', 'project', 'composer_json_sha256', 'composer_lock_sha256'] as $key) {
            unset($sequential['analysis_metadata'][$key], $parallel['analysis_metadata'][$key]);
        }

        self::assertSame($sequential, $parallel);
    }

    public function testEveryPackageIsPlannedAndTheOrderIsKept(): void
    {
        $plan = $this->plan(3);

        self::assertSame(['acme/a', 'acme/b', 'acme/c'], array_map(static fn ($p): string => $p->finding->packageName, $plan->findings));
        foreach ($plan->findings as $finding) {
            self::assertNotNull($finding->recommended(), $finding->finding->packageName . ' must be planned in a worker like any other');
        }
    }

    public function testSolverRunsAreCountedAcrossTheWorkers(): void
    {
        $sequential = $this->plan(1)->metadata['solver_runs'] ?? null;
        $parallel = $this->plan(3)->metadata['solver_runs'] ?? null;

        self::assertNotSame('0', $parallel);
        self::assertSame($sequential, $parallel, 'work done in a child still has to be reported by the parent');
    }

    public function testMoreWorkersThanPackagesIsHarmless(): void
    {
        self::assertCount(3, $this->plan(16)->findings);
    }

    public function testAnAdvisorySourceThatCannotBeForkedIsSaidSoAndPlannedInTurn(): void
    {
        $project = $this->project();
        // The default scripted source does not declare itself fork safe.
        $planner = new Planner(ScriptedProject::advisories(self::advisoryList()), $this->solver(), parallelism: 3);
        $plan = $planner->plan($project->context(), $project->workspace());

        self::assertCount(3, $plan->findings);
        $warnings = implode("\n", $plan->warnings);
        self::assertStringContainsString('one package at a time', $warnings);
        self::assertStringContainsString('scripted advisories', $warnings);
    }

    public function testOneWorkerSaysNothingAboutParallelism(): void
    {
        $plan = $this->plan(1);

        self::assertStringNotContainsString('one package at a time', implode("\n", $plan->warnings), 'the default must not explain itself');
    }

    public function testProgressIsReportedForEveryPackageAsItFinishes(): void
    {
        $project = $this->project();
        $lines = [];
        $planner = new Planner(
            ScriptedProject::advisories(self::advisoryList(), true, true),
            $this->solver(),
            progress: static function (string $message, bool $detail = true) use (&$lines): void {
                if (!$detail) {
                    $lines[] = $message;
                }
            },
            parallelism: 3,
        );
        $planner->plan($project->context(), $project->workspace());

        $headlines = implode("\n", $lines);
        self::assertStringContainsString('3 at a time', $headlines);
        foreach (['acme/a', 'acme/b', 'acme/c'] as $package) {
            self::assertStringContainsString($package, $headlines);
        }
        self::assertStringContainsString('[3/3]', $headlines, 'the count has to reach the total, whatever order the workers finished in');
    }
}
