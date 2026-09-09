<?php

declare(strict_types=1);

namespace Remediate\Command;

use Composer\Command\BaseCommand;
use Remediate\Engine\Advisory\AdvisoryLookupFailed;
use Remediate\Engine\Advisory\ComposerRepositoryAdvisoryProvider;
use Remediate\Engine\Advisory\JsonFileAdvisoryProvider;
use Remediate\Engine\Candidate\CandidateGenerator;
use Remediate\Engine\Plan\Plan;
use Remediate\Engine\Planner;
use Remediate\Engine\Project\ProjectContext;
use Remediate\Engine\Solver\InProcessSolver;
use Remediate\Engine\Solver\ScratchWorkspace;
use Remediate\Output\TextRenderer;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

final class RemediateCommand extends BaseCommand
{
    protected function configure(): void
    {
        $this
            ->setName('remediate')
            ->setDescription('Find the smallest Composer-verified upgrade that removes each known vulnerability from composer.lock')
            ->setDefinition([
                new InputOption('no-dev', null, InputOption::VALUE_NONE, 'Ignore vulnerabilities in require-dev packages'),
                new InputOption('allow-direct-require', null, InputOption::VALUE_NONE, 'Also consider adding a transitive package as a direct requirement to force a fixed version'),
                new InputOption('advisories-file', null, InputOption::VALUE_REQUIRED, 'Read advisories from a JSON file in the Packagist API shape instead of the configured repositories'),
                new InputOption('max-candidates', null, InputOption::VALUE_REQUIRED, 'Maximum number of candidate commands to try per finding', '10'),
                new InputOption('ignore-platform-req', null, InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY, 'Ignore a specific platform requirement (php & ext- packages) when validating candidates'),
                new InputOption('ignore-platform-reqs', null, InputOption::VALUE_NONE, 'Ignore all platform requirements when validating candidates'),
            ])
            ->setHelp(<<<'HELP'
Reads composer.json and composer.lock, matches the locked packages against security advisories,
and for every finding tries a series of <info>composer update</info> commands in a dry-run, from
least to most invasive. Only commands whose resulting lock file no longer contains the
vulnerability are recommended. Nothing in the project is modified.

Exit codes: 0 no vulnerabilities, 1 vulnerabilities with a verified remediation,
2 at least one vulnerability without a verified remediation, 3 error,
4 advisory data unavailable.
HELP);
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = $this->getIO();
        $composer = $this->requireComposer();
        $context = ProjectContext::fromComposer($composer);

        if (!$context->isLocked()) {
            $io->writeError('<error>No composer.lock found. Run composer install or composer update first.</error>');

            return Plan::EXIT_ERROR;
        }

        $advisoriesFile = $input->getOption('advisories-file');
        $advisories = is_string($advisoriesFile) && $advisoriesFile !== ''
            ? new JsonFileAdvisoryProvider($advisoriesFile)
            : ComposerRepositoryAdvisoryProvider::fromRepositoryManager($composer->getRepositoryManager());

        $solver = new InProcessSolver($this->getPlatformRequirementFilter($input));
        $maxCandidates = max(1, (int) $input->getOption('max-candidates'));
        $planner = new Planner(
            $advisories,
            $solver,
            new CandidateGenerator(allowDirectRequire: (bool) $input->getOption('allow-direct-require')),
            !(bool) $input->getOption('no-dev'),
            $maxCandidates,
            static function (string $message) use ($io): void {
                $io->writeError('<comment>' . $message . '</comment>', true, \Composer\IO\IOInterface::VERBOSE);
            },
        );

        try {
            $plan = $planner->plan($context, ScratchWorkspace::fromProject($context));
        } catch (AdvisoryLookupFailed $e) {
            $io->writeError('<error>Advisory data unavailable: ' . $e->getMessage() . '</error>');

            return Plan::EXIT_ADVISORIES_UNAVAILABLE;
        }

        $output->write((new TextRenderer($solver->supportsMinimalChanges()))->render($plan));

        return $plan->exitCode();
    }
}
