<?php

declare(strict_types=1);

namespace Remediate\Tests\Unit\Parallel;

use PHPUnit\Framework\TestCase;
use Remediate\Engine\Parallel\ForkPool;

/**
 * The pool's contract: every job runs, results come back in the order the jobs were given whatever
 * order the children finished in, and a child that fails is reported rather than silently missing.
 */
final class ForkPoolTest extends TestCase
{
    protected function setUp(): void
    {
        $reason = ForkPool::unavailableReason();
        if ($reason !== null) {
            self::markTestSkipped($reason);
        }
    }

    public function testResultsComeBackInTheOrderTheJobsWereGiven(): void
    {
        // The last job finishes first, so a pool that returned completion order would fail this.
        $jobs = [
            0 => static function (): string { usleep(300_000); return 'first'; },
            1 => static function (): string { usleep(150_000); return 'second'; },
            2 => static function (): string { return 'third'; },
        ];

        self::assertSame(['first', 'second', 'third'], array_values((new ForkPool(3))->run($jobs)));
    }

    public function testEveryJobRunsEvenWithOneWorker(): void
    {
        $jobs = [];
        foreach (range(1, 5) as $n) {
            $jobs[] = static fn (): int => $n * $n;
        }

        self::assertSame([1, 4, 9, 16, 25], array_values((new ForkPool(1))->run($jobs)));
    }

    public function testMoreJobsThanWorkersAllRun(): void
    {
        $jobs = [];
        foreach (range(1, 9) as $n) {
            $jobs[] = static fn (): int => $n;
        }

        self::assertSame(range(1, 9), array_values((new ForkPool(2))->run($jobs)));
    }

    public function testChildrenDoNotShareStateWithTheParentOrEachOther(): void
    {
        // A fork copies; it does not share. A child writing to this must not reach the parent.
        $counter = 0;
        $jobs = [];
        foreach (range(1, 3) as $n) {
            $jobs[] = static function () use (&$counter, $n): int {
                $counter += $n;

                return $counter;
            };
        }

        self::assertSame([1, 2, 3], array_values((new ForkPool(3))->run($jobs)), 'each child must start from the parent state, not from a sibling result');
        self::assertSame(0, $counter, 'a child must not be able to write into the parent');
    }

    public function testAThrowingJobFailsTheRunWithItsMessage(): void
    {
        $jobs = [
            static fn (): string => 'fine',
            static function (): string { throw new \DomainException('the child could not plan'); },
        ];

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessageMatches('{DomainException.*the child could not plan}');
        (new ForkPool(2))->run($jobs);
    }

    public function testAChildKilledOutrightIsReportedRatherThanMissing(): void
    {
        // What the out-of-memory killer does to a worker on a large lock file: it dies before it can
        // write anything, and that must surface rather than read as an empty result.
        $jobs = [
            static function (): string {
                posix_kill(posix_getpid(), SIGKILL);

                return 'never reached';
            },
        ];

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessageMatches('{without leaving a result}');
        (new ForkPool(1))->run($jobs);
    }

    public function testAChildDoesNotRunShutdownFunctionsTheParentRegistered(): void
    {
        // A fork inherits them, and the parent's cleanup deletes things the parent is still using.
        $marker = tempnam(sys_get_temp_dir(), 'remediate-shutdown-');
        self::assertIsString($marker);
        $jobs = [
            static function () use ($marker): string {
                register_shutdown_function(static function () use ($marker): void {
                    @unlink($marker);
                });

                return 'done';
            },
        ];

        self::assertSame(['done'], array_values((new ForkPool(1))->run($jobs)));
        self::assertFileExists($marker, 'the child must be stopped before any registered shutdown function can run');
        @unlink($marker);
    }

    public function testTheChildHookRunsBeforeTheJobInEveryChild(): void
    {
        $jobs = [];
        foreach (range(1, 3) as $n) {
            $jobs[] = static fn (): string => $GLOBALS['remediate_test_fork_hook'] ?? 'hook did not run';
        }

        $results = (new ForkPool(2))->run($jobs, null, static function (): void {
            $GLOBALS['remediate_test_fork_hook'] = 'ready';
        });

        self::assertSame(['ready', 'ready', 'ready'], array_values($results));
        self::assertArrayNotHasKey('remediate_test_fork_hook', $GLOBALS, 'the hook must run in the child, not in the parent');
    }

    public function testResultsAreAnnouncedAsTheyArrive(): void
    {
        $seen = [];
        $jobs = [
            0 => static function (): string { usleep(250_000); return 'slow'; },
            1 => static function (): string { return 'quick'; },
        ];

        (new ForkPool(2))->run($jobs, static function (int $key, string $value) use (&$seen): void {
            $seen[] = $value;
        });

        self::assertSame(['quick', 'slow'], $seen, 'progress must be reported in completion order, so a long job does not hold back the news');
    }

    public function testSiblingChildrenDoNotGenerateTheSameRandomNames(): void
    {
        // Every solve runs in a scratch directory named with random_bytes(). Were that drawn from a
        // generator seeded before the fork, siblings would pick the same name and quietly solve in
        // each other's directory. PHP reads the operating system's generator, and this holds it to it.
        $jobs = [];
        foreach (range(1, 6) as $ignored) {
            $jobs[] = static fn (): string => bin2hex(random_bytes(6));
        }

        $names = array_values((new ForkPool(6))->run($jobs));
        self::assertCount(6, array_unique($names), 'two workers drawing the same scratch directory name would corrupt each other');
    }

    public function testAnUnrelatedChildOfThisProcessDoesNotDisturbTheRun(): void
    {
        // The process this runs inside is somebody else's: Composer's, another plugin's. A child of
        // theirs exiting mid-run must not be mistaken for a worker, and its exit status must be left
        // for whoever is waiting on it.
        $foreign = pcntl_fork();
        self::assertNotSame(-1, $foreign, 'could not start the unrelated child this test needs');
        if ($foreign === 0) {
            usleep(120_000);
            posix_kill(posix_getpid(), SIGKILL);
        }

        $jobs = [];
        foreach (range(1, 4) as $n) {
            $jobs[] = static function () use ($n): int {
                usleep(200_000);

                return $n;
            };
        }
        $results = (new ForkPool(2))->run($jobs);

        self::assertSame([1, 2, 3, 4], array_values($results));

        // The pool must not have reaped it: its status is still here to collect.
        $status = 0;
        self::assertSame($foreign, pcntl_waitpid($foreign, $status), 'the unrelated child was reaped by the pool, so its own owner could never learn how it ended');
    }

    public function testNoTemporaryFilesAreLeftBehind(): void
    {
        $before = glob(sys_get_temp_dir() . '/remediate-worker-*') ?: [];
        (new ForkPool(2))->run([static fn (): int => 1, static fn (): int => 2]);
        $after = glob(sys_get_temp_dir() . '/remediate-worker-*') ?: [];

        self::assertSame($before, $after);
    }
}
