<?php

declare(strict_types=1);

namespace Remediate\Engine\Apply;

use Composer\Util\Platform;
use Remediate\Engine\Candidate\Candidate;
use Remediate\Engine\Plan\Plan;
use Remediate\Engine\Project\ProjectContext;
use Symfony\Component\Process\Process;

/**
 * Runs a recommendation against the real project, which is the one thing the rest of this tool never
 * does. It runs the command the report printed, built from the same argument lists, in the project's
 * own Composer, so the result is what the reader would have got by copying the command.
 *
 * Before anything runs: there must be a verified command to run, the manifest and lock must be the
 * ones the plan was computed from, a recommendation that edits `composer.json` needs its own
 * permission, and a git checkout with those files already modified is refused so that an apply is
 * never mixed into someone's uncommitted work. The previous manifest and lock are copied aside first,
 * whatever happens next.
 */
final class Applier
{
    /**
     * @param list<string> $composerCommand   the command prefix that runs Composer (the same one the subprocess solver uses)
     * @param list<string> $safetyArguments   restrictions the run was started with (`--no-plugins`, `--no-scripts`), repeated
     *                                        on every command this applies. An apply must never hold more privilege than the
     *                                        run that planned it: the standalone binary forces both flags precisely so that no
     *                                        code from the analysed project runs, and a subprocess that dropped them would
     *                                        execute that project's scripts and plugins under a promise that it does not.
     */
    public function __construct(
        private readonly array $composerCommand,
        private readonly float $timeout = 900.0,
        private readonly array $safetyArguments = [],
    ) {
    }

    /**
     * Why the plan must not be applied, or null when it may be.
     */
    public function refusal(Plan $plan, ProjectContext $context, bool $allowRootConstraints, bool $allowDirty): ?string
    {
        $combined = $plan->combined;
        if ($combined === null) {
            return $plan->findings === []
                ? 'nothing to apply: no findings.'
                : 'nothing to apply: no verified command was found for these findings. The report lists what was tried.';
        }
        if ($combined->candidate->changesRootConstraints() && !$allowRootConstraints) {
            return sprintf('the recommended command edits composer.json (it widens a root constraint), which --apply does not do on its own. Review it and pass --apply-root-constraints, or run it yourself: %s', $combined->candidate->commandLine());
        }
        foreach ([['composer.json', $context->composerJsonPath()], ['composer.lock', $context->lockPath()]] as [$label, $path]) {
            $expected = $plan->metadata[str_replace('.', '_', $label) . '_sha256'] ?? null;
            $actual = is_file($path) ? hash_file('sha256', $path) : false;
            if (is_string($expected) && $expected !== '' && $actual !== false && !hash_equals($expected, $actual)) {
                return sprintf('%s changed while the plan was being computed; nothing was applied. Run the command again.', $label);
            }
        }
        if (!$allowDirty) {
            $dirty = $this->uncommitted($context->directory);
            if ($dirty !== []) {
                return sprintf('%s already modified in this git checkout; --apply would mix its changes into yours. Commit or stash first, or pass --apply-allow-dirty.', implode(' and ', $dirty));
            }
        }

        return null;
    }

    /**
     * Copies the manifest and lock aside, then runs the recommendation's commands in order, stopping at
     * the first failure. Composer's own output goes to $log as it arrives. With $noInstall the update
     * writes the lock and leaves `vendor/` alone, which is what a pull-request workflow wants.
     *
     * @param callable(string): void $log
     */
    public function apply(Candidate $candidate, ProjectContext $context, bool $minimalChangesSupported, bool $noInstall, callable $log): ApplyResult
    {
        $backup = $this->backup($context);
        $update = $candidate->updateArguments($minimalChangesSupported);
        if ($noInstall) {
            $update[] = '--no-install';
        }
        $lists = [...$candidate->requireArgumentLists(), $update];
        $ran = [];
        foreach ($lists as $arguments) {
            // --no-interaction so an apply never blocks on a prompt; everything else is the printed
            // command, and what is recorded is the whole of what ran, appended flags included.
            $arguments[] = '--no-interaction';
            array_push($arguments, ...$this->safetyArguments);
            $argv = [...$this->composerCommand, ...$arguments];
            // Rendered the same way the recommendation is printed, so what the report says ran can be
            // pasted back and mean the same thing. Joining with spaces would drop the quoting a
            // constraint needs and quietly change the command.
            $ran[] = Candidate::render($arguments);
            $process = new Process($argv, $context->directory, $this->environment(), null, $this->timeout);
            $log('running: ' . end($ran));
            $process->run(static function (string $type, string $buffer) use ($log): void {
                $log(rtrim($buffer, "\n"));
            });
            if (!$process->isSuccessful()) {
                return new ApplyResult(ApplyOutcome::Failed, $ran, $backup, sprintf('%s exited %s. The project is as Composer left it; the files from before the run are in %s.', end($ran), $process->getExitCode() ?? '?', $backup));
            }
        }

        return new ApplyResult(ApplyOutcome::Applied, $ran, $backup);
    }

    /**
     * The manifest and lock, copied into a new directory outside the project. Nothing is written into
     * the project that was not there before, so an apply leaves no files of ours behind.
     */
    private function backup(ProjectContext $context): string
    {
        $directory = sys_get_temp_dir() . '/remediate-backup-' . gmdate('Ymd-His') . '-' . bin2hex(random_bytes(3));
        if (!@mkdir($directory, 0700, true)) {
            throw new \RuntimeException(sprintf('Cannot create the backup directory %s; nothing was applied.', $directory));
        }
        foreach ([$context->composerJsonPath(), $context->lockPath()] as $path) {
            if (is_file($path) && !@copy($path, $directory . '/' . basename($path))) {
                throw new \RuntimeException(sprintf('Cannot copy %s into %s; nothing was applied.', $path, $directory));
            }
        }

        return $directory;
    }

    /**
     * Which of the manifest and lock a git checkout reports as modified, so that an apply is never
     * mixed into someone's uncommitted work.
     *
     * git itself answers whether this is a checkout: asking it covers a worktree or a submodule, where
     * `.git` is a file rather than a directory, and a project nested below the repository root, where
     * there is no `.git` entry beside the manifest at all. A directory that is not in a checkout, or a
     * machine without git, answers with a failure and nothing to mix into. Untracked files are not
     * modifications: there is no committed state of theirs to disturb.
     *
     * @return list<string>
     */
    private function uncommitted(string $directory): array
    {
        $process = new Process(['git', 'status', '--porcelain', '--', 'composer.json', 'composer.lock'], $directory, null, null, 30.0);
        try {
            $process->run();
        } catch (\Throwable) {
            return [];
        }
        if (!$process->isSuccessful()) {
            return [];
        }
        $modified = [];
        foreach (explode("\n", trim($process->getOutput())) as $line) {
            if (str_starts_with($line, '??')) {
                continue;
            }
            $name = trim(substr($line, 2));
            if ($name !== '') {
                $modified[] = $name;
            }
        }

        return $modified;
    }

    /**
     * The environment for the child: this process's, plus every COMPOSER_* variable set at runtime with
     * putenv(), which is not in $_SERVER and would otherwise not reach it.
     *
     * @return array<string, string>
     */
    private function environment(): array
    {
        $environment = [];
        foreach (['COMPOSER', 'COMPOSER_HOME', 'COMPOSER_CACHE_DIR', 'COMPOSER_AUTH', 'COMPOSER_DISABLE_NETWORK', 'COMPOSER_CAFILE', 'COMPOSER_MEMORY_LIMIT'] as $name) {
            $value = Platform::getEnv($name);
            if (is_string($value) && $value !== '') {
                $environment[$name] = $value;
            }
        }

        return $environment;
    }
}
