<?php

declare(strict_types=1);

namespace Remediate\Tests\Unit\Apply;

use Composer\DependencyResolver\Request;
use PHPUnit\Framework\TestCase;
use Remediate\Engine\Apply\Applier;
use Remediate\Engine\Apply\ApplyOutcome;
use Remediate\Engine\Candidate\Candidate;
use Remediate\Engine\Candidate\RootConstraintChange;
use Remediate\Engine\Candidate\Strategy;
use Remediate\Engine\Lock\LockSnapshot;
use Remediate\Engine\Plan\CombinedRemediation;
use Remediate\Engine\Plan\Plan;
use Remediate\Engine\Project\ProjectContext;
use Remediate\Tests\Support\FakeSolver;
use Remediate\Engine\Planner;
use Remediate\Engine\Solver\LockDiff;
use Remediate\Engine\Solver\SolveResult;
use Remediate\Engine\Solver\SolveStatus;
use Remediate\Tests\Support\ScriptedProject;
use Symfony\Component\Process\Process;

/**
 * What --apply refuses to do, and what it leaves behind when it runs. The preconditions are the
 * feature's whole safety story, so each has its own case.
 */
final class ApplierTest extends TestCase
{
    /** @var list<ScriptedProject> */
    private array $projects = [];
    /** @var list<string> */
    private array $backups = [];

    protected function tearDown(): void
    {
        foreach ($this->projects as $project) {
            $project->destroy();
        }
        foreach ($this->backups as $directory) {
            foreach (glob($directory . '/*') ?: [] as $file) {
                @unlink($file);
            }
            @rmdir($directory);
        }
    }

    private function project(): ProjectContext
    {
        $project = $this->projects[] = new ScriptedProject(['acme/lib' => '^1.0'], [['acme/lib', '1.0.0']]);

        return $project->context();
    }

    private static function candidate(bool $rootChange = false): Candidate
    {
        return new Candidate(
            Strategy::LockRefresh,
            ['acme/lib'],
            Request::UPDATE_ONLY_LISTED,
            [],
            false,
            $rootChange ? ['acme/lib' => new RootConstraintChange('acme/lib', '^1.0', '^2.0', false)] : [],
            'x',
        );
    }

    /** A plan whose combined command is the given candidate, with digests matching the project on disk. */
    private static function plan(ProjectContext $context, ?Candidate $candidate): Plan
    {
        $before = LockSnapshot::fromPackages([], []);
        $combined = $candidate === null ? null : new CombinedRemediation($candidate, new SolveResult(SolveStatus::Resolved, $before, ''), LockDiff::between($before, $before), ['PKSA-1@acme/lib'], []);
        $metadata = [
            'composer_json_sha256' => (string) hash_file('sha256', $context->composerJsonPath()),
            'composer_lock_sha256' => (string) hash_file('sha256', $context->lockPath()),
        ];

        return new Plan([], $metadata, [], $combined);
    }

    private function applier(): Applier
    {
        return new Applier([PHP_BINARY, '-r', 'exit(0);']);
    }

    public function testNothingVerifiedToRunIsRefusedWithTheReason(): void
    {
        $context = $this->project();
        $reason = $this->applier()->refusal(self::plan($context, null), $context, false, true);

        self::assertNotNull($reason);
        self::assertStringContainsString('no findings', $reason, 'a clean project says so rather than sounding like a failure');
    }

    public function testACommandThatEditsComposerJsonNeedsItsOwnPermission(): void
    {
        $context = $this->project();
        $plan = self::plan($context, self::candidate(true));

        $reason = $this->applier()->refusal($plan, $context, false, true);
        self::assertNotNull($reason);
        self::assertStringContainsString('edits composer.json', $reason);
        self::assertStringContainsString('--apply-root-constraints', $reason);
        self::assertStringContainsString('composer require --no-update acme/lib:^2.0', $reason, 'the command is printed so it can be run by hand');

        self::assertNull($this->applier()->refusal($plan, $context, true, true), 'with the permission it may run');
    }

    public function testAManifestThatChangedSinceThePlanIsRefused(): void
    {
        $context = $this->project();
        // The digests in the plan are the files as they were; the manifest then changes underneath it.
        $plan = self::plan($context, self::candidate());
        file_put_contents($context->composerJsonPath(), (string) file_get_contents($context->composerJsonPath()) . "\n");
        $reason = $this->applier()->refusal($plan, $context, false, true);

        self::assertNotNull($reason);
        self::assertStringContainsString('composer.json changed while the plan was being computed', $reason);
    }

    public function testAGitCheckoutWithThoseFilesAlreadyModifiedIsRefused(): void
    {
        $context = $this->project();
        $git = new Process(['git', 'init', '-q'], $context->directory);
        $git->run();
        if (!$git->isSuccessful()) {
            self::markTestSkipped('git is not available');
        }
        foreach ([['git', 'add', '-A'], ['git', '-c', 'user.email=t@t', '-c', 'user.name=t', 'commit', '-qm', 'x']] as $argv) {
            (new Process($argv, $context->directory))->run();
        }
        $plan = self::plan($context, self::candidate());
        self::assertNull($this->applier()->refusal($plan, $context, false, false), 'a clean checkout is fine');

        file_put_contents($context->lockPath(), (string) file_get_contents($context->lockPath()) . "\n");
        $dirty = self::plan($context, self::candidate());

        $reason = $this->applier()->refusal($dirty, $context, false, false);
        self::assertNotNull($reason);
        self::assertStringContainsString('composer.lock already modified in this git checkout', $reason);
        self::assertStringContainsString('--apply-allow-dirty', $reason);
        self::assertNull($this->applier()->refusal($dirty, $context, false, true), 'unless the operator said to');
    }

    public function testAWorktreeOrSubmoduleCheckoutIsStillAGitCheckout(): void
    {
        // In a worktree or a submodule `.git` is a file naming the real git directory elsewhere. A test
        // for a `.git` directory misses those, and the refusal would be skipped exactly where a user is
        // most likely to have work in progress.
        $context = $this->project();
        $git = new Process(['git', 'init', '-q'], $context->directory);
        $git->run();
        if (!$git->isSuccessful()) {
            self::markTestSkipped('git is not available');
        }
        foreach ([['git', 'add', '-A'], ['git', '-c', 'user.email=t@t', '-c', 'user.name=t', 'commit', '-qm', 'x']] as $argv) {
            (new Process($argv, $context->directory))->run();
        }
        rename($context->directory . '/.git', $context->directory . '/.git-real');
        file_put_contents($context->directory . '/.git', 'gitdir: ' . $context->directory . '/.git-real' . "\n");
        file_put_contents($context->lockPath(), (string) file_get_contents($context->lockPath()) . "\n");

        $reason = $this->applier()->refusal(self::plan($context, self::candidate()), $context, false, false);

        self::assertNotNull($reason, 'git answers for a worktree as readily as for a plain checkout');
        self::assertStringContainsString('composer.lock already modified', $reason);
    }

    public function testAnUntrackedManifestIsNotAModification(): void
    {
        // Nothing committed to disturb: a library that keeps composer.lock out of the repository, or a
        // project added to a checkout but not yet committed, must not be refused.
        $context = $this->project();
        $git = new Process(['git', 'init', '-q'], $context->directory);
        $git->run();
        if (!$git->isSuccessful()) {
            self::markTestSkipped('git is not available');
        }

        self::assertNull($this->applier()->refusal(self::plan($context, self::candidate()), $context, false, false));
    }

    public function testADirectoryOutsideAnyCheckoutIsNotRefused(): void
    {
        $context = $this->project();

        self::assertNull($this->applier()->refusal(self::plan($context, self::candidate()), $context, false, false), 'no checkout, nothing to mix into');
    }

    public function testTheManifestAndLockAreCopiedAsideBeforeAnythingRuns(): void
    {
        $context = $this->project();
        $manifest = (string) file_get_contents($context->composerJsonPath());

        $result = $this->applier()->apply(self::candidate(), $context, true, true, static function (): void {
        });

        self::assertSame(ApplyOutcome::Applied, $result->outcome);
        $backup = (string) $result->backup;
        $this->backups[] = $backup;
        self::assertStringEqualsFile($backup . '/composer.json', $manifest);
        self::assertFileExists($backup . '/composer.lock');
        self::assertStringStartsNotWith($context->directory . '/', $backup, 'nothing of ours is left inside the project');
        self::assertSame(['composer update acme/lib --no-install --no-interaction'], $result->commands, 'what ran is recorded in full');
    }

    public function testAFailingCommandIsReportedWithTheBackupPath(): void
    {
        $context = $this->project();
        $applier = new Applier([PHP_BINARY, '-r', 'exit(1);']);

        $result = $applier->apply(self::candidate(), $context, true, false, static function (): void {
        });

        self::assertSame(ApplyOutcome::Failed, $result->outcome);
        $backup = (string) $result->backup;
        $this->backups[] = $backup;
        self::assertStringContainsString('exited 1', (string) $result->reason);
        self::assertStringContainsString($backup, (string) $result->reason);
    }

    /**
     * Recheck of the eighth review, finding 3. The hash comparison was skipped when the file could not
     * be read at all, so deleting composer.lock while the search ran passed the guard: the strongest
     * evidence that something interfered was treated as agreement.
     */
    public function testAPlanningInputThatDisappearedIsARefusal(): void
    {
        $project = new ScriptedProject(['acme/pkg' => '^1.0'], [['acme/pkg', '1.0.0']]);
        try {
            $context = $project->context();
            $plan = (new Planner(
                ScriptedProject::advisories([ScriptedProject::advisory('TEST-1', 'acme/pkg', '<1.1.0')]),
                new FakeSolver(new SolveResult(SolveStatus::Resolved, ScriptedProject::lock([['acme/pkg', '1.1.0']]), '')),
            ))->plan($context, $project->workspace());
            self::assertNotNull($plan->combined, 'there is something to apply, so the guard is what stands in the way');

            unlink($context->lockPath());

            self::assertSame(
                'composer.lock is missing or unreadable; the plan was computed from it, so nothing was applied. Run the command again.',
                (new Applier(['composer']))->refusal($plan, $context, false, true),
            );
        } finally {
            $project->destroy();
        }
    }
}
