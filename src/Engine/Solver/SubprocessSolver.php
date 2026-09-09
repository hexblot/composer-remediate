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

    public function __construct(
        private readonly string $composerBinary = 'composer',
        private readonly float $timeout = 600.0,
        /** @var list<string> extra arguments such as --ignore-platform-req=php */
        private readonly array $extraArguments = [],
    ) {
    }

    public function supportsMinimalChanges(): bool
    {
        if ($this->minimalChanges === null) {
            $process = new Process([$this->composerBinary, '--version', '--no-ansi']);
            $process->run();
            $this->minimalChanges = preg_match('{Composer(?: version)? (\d+)\.(\d+)}', $process->getOutput(), $m) === 1
                && ((int) $m[1] > 2 || ((int) $m[1] === 2 && (int) $m[2] >= 9));
        }

        return $this->minimalChanges;
    }

    public function describe(): string
    {
        return sprintf('`%s update --no-install` in a scratch directory', $this->composerBinary);
    }

    public function solve(Candidate $candidate, ScratchWorkspace $workspace): SolveResult
    {
        $project = $workspace->materialize();
        try {
            foreach ($candidate->rootConstraintChanges as $change) {
                $project->changeRootRequirement($change->packageName, $change->toConstraint, $change->isDev);
            }

            $args = [$this->composerBinary, 'update', ...$candidate->allowList, '--no-install', '--no-scripts', '--no-plugins', '--no-audit', '--no-progress', '--no-interaction', '--no-ansi'];
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
            array_push($args, ...$this->extraArguments);

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
