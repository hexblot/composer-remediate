<?php

declare(strict_types=1);

namespace Remediate\Engine\Solver;

use Composer\Composer;
use Composer\Downloader\TransportException;
use Composer\Factory;
use Composer\Filter\PlatformRequirementFilter\PlatformRequirementFilterFactory;
use Composer\Filter\PlatformRequirementFilter\PlatformRequirementFilterInterface;
use Composer\Installer;
use Composer\IO\BufferIO;
use Composer\IO\NullIO;
use Composer\Policy\PolicyConfig;
use Composer\Semver\Intervals;
use Composer\Semver\VersionParser;
use Remediate\Engine\Candidate\Candidate;
use Remediate\Engine\Lock\LockSnapshot;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Runs Composer's Installer against a scratch copy and reads the resulting lock: from memory after a
 * dry run on Composer >= 2.9, from the lock file written into the scratch copy on older releases.
 * Nothing is installed and the user's project is never touched. Advisory blocking (Composer >= 2.10) is
 * disabled for the solve so behaviour is identical across Composer versions; the planner performs
 * its own advisory check on the result.
 */
final class InProcessSolver implements SolverInterface
{
    private readonly PlatformRequirementFilterInterface $platformFilter;

    public function __construct(?PlatformRequirementFilterInterface $platformFilter = null)
    {
        $this->platformFilter = $platformFilter ?? PlatformRequirementFilterFactory::ignoreNothing();
    }

    public function supportsMinimalChanges(): bool
    {
        // Composer < 2.9 has no --minimal-changes; this guard is redundant against the dev dependency but not at runtime.
        return method_exists(Installer::class, 'setMinimalUpdate'); // @phpstan-ignore function.alreadyNarrowedType
    }

    public function describe(): string
    {
        return sprintf('in-process Composer %s dry-run', Composer::getVersion());
    }

    public function solve(Candidate $candidate, ScratchWorkspace $workspace): SolveResult
    {
        $project = $workspace->materialize();
        try {
            foreach ($candidate->rootConstraintChanges as $change) {
                $project->changeRootRequirement($change->packageName, $change->toConstraint, $change->isDev);
            }

            $io = new BufferIO('', OutputInterface::VERBOSITY_NORMAL);
            try {
                $composer = Factory::create($io, $project->composerJsonPath(), true, true);
            } catch (\Throwable $e) {
                return new SolveResult(SolveStatus::Error, null, $io->getOutput(), 'Composer could not load the scratch project: ' . $e->getMessage());
            }

            // Composer >= 2.9 exposes the solved lock in memory after a dry run. Older releases do
            // not, so there the update writes composer.lock into the scratch copy (never the user's
            // project) and the result is read back from that file.
            $inMemory = method_exists(Installer::class, 'getLockTransaction'); // @phpstan-ignore function.alreadyNarrowedType
            $installer = Installer::create($io, $composer);
            $installer
                ->setDryRun($inMemory)
                ->setUpdate(true)
                ->setInstall(false)
                ->setWriteLock(!$inMemory)
                ->setExecuteOperations(false)
                ->setDevMode(true)
                ->setDumpAutoloader(false)
                ->setRunScripts(false)
                ->setAudit(false)
                ->setUpdateAllowList($candidate->allowList)
                ->setUpdateAllowTransitiveDependencies($candidate->transitiveMode)
                ->setPlatformRequirementFilter($this->platformFilter);

            $temporary = $candidate->effectiveTemporaryConstraints();
            if ($temporary !== []) {
                $parser = new VersionParser();
                $constraints = [];
                foreach ($temporary as $name => $expression) {
                    $constraints[$name] = $parser->parseConstraints($expression);
                }
                $installer->setTemporaryConstraints($constraints);
            }
            if ($candidate->minimalChanges && $this->supportsMinimalChanges()) {
                $installer->setMinimalUpdate(true);
            }
            // Composer < 2.10 has neither policy blocking nor setPolicyConfig().
            if (class_exists(PolicyConfig::class) && method_exists($installer, 'setPolicyConfig')) { // @phpstan-ignore function.alreadyNarrowedType
                $installer->setPolicyConfig(PolicyConfig::fromConfig($composer->getConfig())->withBlockingDisabled());
            }

            try {
                $code = $installer->run();
            } catch (TransportException $e) {
                return new SolveResult(SolveStatus::Transport, null, $io->getOutput(), $e->getMessage(), $e->getCode());
            } catch (\Throwable $e) {
                return new SolveResult(SolveStatus::Error, null, $io->getOutput(), get_class($e) . ': ' . $e->getMessage());
            } finally {
                Intervals::clear();
            }

            if ($code !== 0) {
                $status = match ($code) {
                    Installer::ERROR_DEPENDENCY_RESOLUTION_FAILED => SolveStatus::Conflict,
                    Installer::ERROR_TRANSPORT_EXCEPTION => SolveStatus::Transport,
                    default => SolveStatus::Error,
                };

                return new SolveResult($status, null, $io->getOutput(), null, $code);
            }

            if ($inMemory) {
                $transaction = $installer->getLockTransaction();
                if ($transaction === null) {
                    return new SolveResult(SolveStatus::Error, null, $io->getOutput(), 'Composer reported success but produced no lock transaction.');
                }
                $after = LockSnapshot::fromPackages($transaction->getNewLockPackages(false), $transaction->getNewLockPackages(true));
            } else {
                try {
                    $reloaded = Factory::create(new NullIO(), $project->composerJsonPath(), true, true);
                    $after = LockSnapshot::fromLocker($reloaded->getLocker());
                } catch (\Throwable $e) {
                    return new SolveResult(SolveStatus::Error, null, $io->getOutput(), 'Could not read the lock file written by the solve: ' . $e->getMessage());
                }
            }

            return new SolveResult(SolveStatus::Resolved, $after, $io->getOutput());
        } finally {
            $project->destroy();
        }
    }
}
