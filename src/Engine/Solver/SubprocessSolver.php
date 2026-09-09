<?php

declare(strict_types=1);

namespace Remediate\Engine\Solver;

use Composer\DependencyResolver\Request;
use Composer\Factory;
use Composer\IO\NullIO;
use Remediate\Engine\Candidate\Candidate;
use Remediate\Engine\Lock\LockSnapshot;
use Symfony\Component\Process\Process;

/**
 * Fallback solver: runs the real `composer update --no-install` in a scratch copy and reads the
 * lock file it writes. Slower than InProcessSolver but independent of Composer's PHP API.
 */
final class SubprocessSolver implements SolverInterface
{
    private ?bool $minimalChanges = null;

    /** @var list<string> */
    private readonly array $composerCommand;

    /**
     * @param list<string>|string $composer       the Composer executable, or the command prefix that runs it (e.g. [php, composer.phar])
     * @param list<string>        $extraArguments extra arguments such as --ignore-platform-req=php
     */
    public function __construct(
        array|string $composer = 'composer',
        private readonly float $timeout = 600.0,
        private readonly array $extraArguments = [],
    ) {
        $this->composerCommand = is_string($composer) ? [$composer] : $composer;
    }

    /**
     * The Composer executable that is running this process (the phar or source checkout behind the
     * `composer` command), so the subprocess uses the same Composer version as the in-process solver.
     */
    public static function forRunningComposer(?string $composerBinary = null): self
    {
        $env = getenv('REMEDIATE_COMPOSER_BINARY');
        $script = $composerBinary ?? (is_string($env) && $env !== '' ? $env : (is_string($_SERVER['argv'][0] ?? null) ? $_SERVER['argv'][0] : 'composer'));
        if (str_contains($script, '/') || is_file($script)) {
            $script = realpath($script) ?: $script;

            return new self(is_executable($script) ? [$script] : [PHP_BINARY, $script]);
        }

        return new self([$script]);
    }

    public function supportsMinimalChanges(): bool
    {
        if ($this->minimalChanges === null) {
            $process = new Process([...$this->composerCommand, '--version', '--no-ansi']);
            $process->run();
            // --minimal-changes exists since Composer 2.7.0 (2.9 extended it to full updates).
            $this->minimalChanges = preg_match('{Composer(?: version)? (\d+)\.(\d+)}', $process->getOutput(), $m) === 1
                && ((int) $m[1] > 2 || ((int) $m[1] === 2 && (int) $m[2] >= 7));
        }

        return $this->minimalChanges;
    }

    public function describe(): string
    {
        return sprintf('`%s update --no-install` in a scratch directory', implode(' ', array_map('basename', $this->composerCommand)));
    }

    public function solve(Candidate $candidate, ScratchWorkspace $workspace): SolveResult
    {
        $project = $workspace->materialize();
        try {
            foreach ($candidate->rootConstraintChanges as $change) {
                $project->changeRootRequirement($change->packageName, $change->toConstraint, $change->isDev);
            }

            $args = [...$this->composerCommand, 'update', ...$candidate->allowList, '--no-install', '--no-scripts', '--no-plugins', '--no-audit', '--no-progress', '--no-interaction', '--no-ansi'];
            if ($candidate->transitiveMode === Request::UPDATE_LISTED_WITH_TRANSITIVE_DEPS) {
                $args[] = '--with-all-dependencies';
            } elseif ($candidate->transitiveMode === Request::UPDATE_LISTED_WITH_TRANSITIVE_DEPS_NO_ROOT_REQUIRE) {
                $args[] = '--with-dependencies';
            }
            if ($candidate->minimalChanges && $this->supportsMinimalChanges()) {
                $args[] = '--minimal-changes';
            }
            foreach ($candidate->effectiveTemporaryConstraints() as $name => $constraint) {
                $args[] = '--with';
                $args[] = $name . ':' . $constraint;
            }
            array_push($args, ...$candidate->extraArguments, ...$this->extraArguments);

            $process = new Process($args, $project->directory(), [
                'COMPOSER_NO_INTERACTION' => '1',
                'COMPOSER_NO_BLOCKING' => '1',
                'COMPOSER_NO_SECURITY_BLOCKING' => '1',
            ], null, $this->timeout);
            $process->run();
            $output = $process->getOutput() . $process->getErrorOutput();
            $code = $process->getExitCode() ?? 1;

            if ($code !== 0) {
                $status = match ($code) {
                    2 => SolveStatus::Conflict,
                    100 => SolveStatus::Transport,
                    default => SolveStatus::Error,
                };

                return new SolveResult($status, null, $output, null, $code);
            }

            try {
                $composer = Factory::create(new NullIO(), $project->composerJsonPath(), true, true);
                $after = LockSnapshot::fromLocker($composer->getLocker());
            } catch (\Throwable $e) {
                return new SolveResult(SolveStatus::Error, null, $output, 'Could not read the resulting lock file: ' . $e->getMessage());
            }

            return new SolveResult(SolveStatus::Resolved, $after, $output);
        } finally {
            $project->destroy();
        }
    }
}
