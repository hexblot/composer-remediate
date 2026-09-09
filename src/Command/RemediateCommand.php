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
use Remediate\Output\ReportFormat;
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
                new InputOption('format', 'f', InputOption::VALUE_REQUIRED, 'Format printed to standard output: text, html, json or none', 'text'),
                new InputOption('output', 'o', InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY, 'Also write a report file; format inferred from the extension (.html, .json, .txt) or given as html:path. Repeatable.'),
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
        $format = ReportFormat::tryFrom(strtolower((string) $input->getOption('format')));
        if ($format === null) {
            $io->writeError(sprintf('<error>Unknown format "%s"; use text, html, json or none.</error>', (string) $input->getOption('format')));

            return Plan::EXIT_ERROR;
        }
        $outputs = [];
        foreach ((array) $input->getOption('output') as $spec) {
            if (!is_string($spec) || $spec === '') {
                continue;
            }
            try {
                $outputs[] = ReportFormat::parseOutputSpec($spec);
            } catch (\InvalidArgumentException $e) {
                $io->writeError('<error>' . $e->getMessage() . '</error>');

                return Plan::EXIT_ERROR;
            }
        }
        if (PHP_VERSION_ID < 80200) {
            $io->writeError(sprintf('<warning>PHP %s is end of life and no longer receives security fixes; upgrade the runtime that executes Composer.</warning>', PHP_VERSION));
        }
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

        $minimal = $solver->supportsMinimalChanges();
        foreach ($outputs as [$fileFormat, $path]) {
            if ($path === null || $fileFormat === ReportFormat::None) {
                continue;
            }
            if (@file_put_contents($path, $fileFormat->render($plan, $minimal)) === false) {
                $io->writeError(sprintf('<error>Could not write %s report to %s</error>', $fileFormat->value, $path));

                return Plan::EXIT_ERROR;
            }
            $io->writeError(sprintf('%s report written to %s', ucfirst($fileFormat->value), $path));
        }
        if ($format !== ReportFormat::None) {
            $output->write($format->render($plan, $minimal));
        }

        return $plan->exitCode();
    }
}
