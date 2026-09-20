<?php

declare(strict_types=1);

namespace Remediate\Tests\Unit\Engine;

use PHPUnit\Framework\TestCase;
use Remediate\Engine\Advisory\Db\AffectedRange;
use Remediate\Engine\Advisory\Db\Database;
use Remediate\Engine\Advisory\Db\DatabaseBuilder;
use Remediate\Engine\Advisory\Db\NormalizedAdvisory;
use Remediate\Engine\Advisory\Db\Source\AdvisorySourceInterface;
use Remediate\Engine\Advisory\Db\SourceRecord;
use Remediate\Engine\Advisory\Db\SqliteAdvisoryProvider;
use Remediate\Engine\Parallel\ForkPool;
use Remediate\Engine\Planner;
use Remediate\Output\JsonRenderer;
use Remediate\Tests\Support\FakeSolver;
use Remediate\Tests\Support\KilledOnceSolver;
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

    public function testAWorkerThatDiesDoesNotCostTheRun(): void
    {
        // What the out-of-memory killer does to a worker on a large lock file. The packages already
        // finished are kept and the rest are planned here, rather than an hour of solving being lost.
        $plan = $this->planWithAWorkerThatDies();

        self::assertCount(3, $plan->findings, 'every package is planned, one way or the other');
        foreach ($plan->findings as $finding) {
            self::assertNotNull($finding->recommended(), $finding->finding->packageName);
        }
        self::assertStringContainsString('planned one at a time instead', implode("\n", $plan->warnings), 'the report has to say the run degraded');
    }

    public function testADegradedRunDoesNotCountTheWorkItRedoesTwice(): void
    {
        // The worker is killed before it finishes a single solve, so a degraded run does exactly the
        // work a healthy one does. The count has to say so. A package re-planned in this process has
        // already counted its own solves; counting its total again reported solver runs that never
        // happened, in the metadata whose whole purpose is to let someone reproduce the run.
        $healthy = $this->plan(3);
        $degraded = $this->planWithAWorkerThatDies();

        self::assertSame(
            $healthy->metadata['solver_runs'],
            $degraded->metadata['solver_runs'],
            'the same work, counted twice because a worker died',
        );
    }

    private function planWithAWorkerThatDies(): \Remediate\Engine\Plan\Plan
    {
        $project = $this->project();
        $planner = new Planner(
            ScriptedProject::advisories(self::advisoryList(), true, true),
            new KilledOnceSolver($this->solver()),
            parallelism: 3,
        );

        return $planner->plan($project->context(), $project->workspace());
    }

    public function testTheSqliteAdvisoryDatabaseSurvivesTheFork(): void
    {
        // The configuration every real user runs: the published SQLite database plus --parallelize.
        // It had no coverage at all, which is what this closes.
        //
        // It does not prove that the reconnect in afterFork() is what makes it work: the test still
        // passes with that line removed, because a read-only SQLite handle inherited across a fork
        // usually appears to work. That is precisely why the reconnect is there. SQLite's own
        // documentation says not to carry a connection across a fork, and the failure it warns about
        // is nondeterministic and platform-dependent, so the reconnect answers the documented rule
        // rather than an observed crash.
        $file = sys_get_temp_dir() . '/composer-remediate-parallel-db-' . bin2hex(random_bytes(4)) . '.sqlite';
        $advisories = [];
        foreach (['acme/a', 'acme/b', 'acme/c'] as $package) {
            $advisories[] = new NormalizedAdvisory(
                'CVE-2026-' . substr($package, -1),
                ['CVE-2026-' . substr($package, -1)],
                'vulnerable',
                null,
                'high',
                null,
                null,
                [new AffectedRange($package, '<1.1.0', 'Upstream')],
                [new SourceRecord('Upstream', 'CVE-2026-' . substr($package, -1))],
            );
        }
        (new DatabaseBuilder([$this->fixedSource($advisories)]))->build($file, static function (): void {
        });

        try {
            $project = $this->project();
            $planner = new Planner(
                new SqliteAdvisoryProvider(Database::open($file)),
                $this->solver(),
                parallelism: 3,
            );
            $plan = $planner->plan($project->context(), $project->workspace());

            self::assertCount(3, $plan->findings, 'the database answered in every worker');
            foreach ($plan->findings as $finding) {
                self::assertNotNull($finding->recommended(), $finding->finding->packageName);
            }
            self::assertSame([], array_values(array_filter($plan->warnings, static fn (string $w): bool => str_contains($w, 'one package at a time'))), 'a database-backed run must actually fan out');
        } finally {
            @unlink($file);
        }
    }

    /** @param list<NormalizedAdvisory> $records */
    private function fixedSource(array $records): AdvisorySourceInterface
    {
        return new class($records) implements AdvisorySourceInterface {
            /** @param list<NormalizedAdvisory> $records */
            public function __construct(private readonly array $records)
            {
            }

            public function name(): string
            {
                return 'Upstream';
            }

            public function fetch(callable $log): array
            {
                return $this->records;
            }

            public function gaps(): array
            {
                return [];
            }
        };
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
