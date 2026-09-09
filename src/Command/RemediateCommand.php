<?php

declare(strict_types=1);

namespace Remediate\Command;

use Composer\Command\BaseCommand;
use Composer\Config;
use Composer\Util\Platform;
use Remediate\Engine\Advisory\AdvisoryLookupFailed;
use Composer\Factory;
use Remediate\Engine\Advisory\ComposerRepositoryAdvisoryProvider;
use Remediate\Engine\Advisory\Db\Database;
use Remediate\Engine\Advisory\Db\DatabaseLocator;
use Remediate\Engine\Advisory\Db\SqliteAdvisoryProvider;
use Remediate\Engine\Advisory\JsonFileAdvisoryProvider;
use Remediate\Engine\Candidate\CandidateGenerator;
use Remediate\Engine\Plan\Plan;
use Remediate\Engine\Planner;
use Remediate\Engine\Project\ProjectContext;
use Remediate\Engine\Solver\InProcessSolver;
use Remediate\Engine\Solver\ScratchWorkspace;
use Remediate\Output\LockLineIndex;
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
                new InputOption('format', 'f', InputOption::VALUE_REQUIRED, 'Format printed to standard output: text, html, json, sarif, cyclonedx or none', 'text'),
                new InputOption('output', 'o', InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY, 'Also write a report file; format inferred from the extension (.html, .json, .sarif, .cdx.json, .txt) or given as sarif:path. Repeatable.'),
                new InputOption('fail-on', null, InputOption::VALUE_REQUIRED, 'Only findings at or above this severity (low, medium, high, critical) affect the exit code; findings of unknown severity always count'),
                new InputOption('no-dev', null, InputOption::VALUE_NONE, 'Ignore vulnerabilities in require-dev packages'),
                new InputOption('offline', null, InputOption::VALUE_NONE, 'Refuse all network access; needs a warm Composer cache plus --advisories-file or --database-location (sets COMPOSER_DISABLE_NETWORK=1)'),
                new InputOption('ignore', 'i', InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY, 'Advisory id or CVE to ignore (repeatable); config.audit.ignore and config.policy.advisories.ignore are honoured as well'),
                new InputOption('allow-direct-require', null, InputOption::VALUE_NONE, 'Also consider adding a transitive package as a direct requirement to force a fixed version'),
                new InputOption('advisories-file', null, InputOption::VALUE_REQUIRED, 'Read advisories from a JSON file in the Packagist API shape instead of the configured repositories'),
                new InputOption('database-location', null, InputOption::VALUE_REQUIRED, 'Read advisories from a local advisory database (path or URL) built with remediate:db-build; also REMEDIATE_DATABASE or extra.remediate.database'),
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
4 advisory data unavailable, 5 package metadata could not be fetched while solving.
HELP);
    }

    /**
     * Advisory ids from config.audit.ignore (Composer <= 2.9) and config.policy.advisories.ignore /
     * ignore-id (Composer >= 2.10), in either list or map form.
     *
     * @return list<string>
     */
    private static function configuredIgnores(Config $config): array
    {
        $ids = [];
        $collect = static function (mixed $value) use (&$ids): void {
            if (!is_array($value)) {
                return;
            }
            foreach ($value as $key => $entry) {
                if (is_string($key)) {
                    $ids[] = $key;
                } elseif (is_string($entry)) {
                    $ids[] = $entry;
                }
            }
        };
        $audit = $config->get('audit');
        if (is_array($audit)) {
            $collect($audit['ignore'] ?? null);
        }
        $policy = $config->has('policy') ? $config->get('policy') : null;
        if (is_array($policy) && is_array($policy['advisories'] ?? null)) {
            $collect($policy['advisories']['ignore'] ?? null);
            $collect($policy['advisories']['ignore-id'] ?? null);
        }

        return array_values(array_unique($ids));
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = $this->getIO();
        $format = ReportFormat::tryFrom(strtolower((string) $input->getOption('format')));
        if ($format === null) {
            $io->writeError(sprintf('<error>Unknown format "%s"; use text, html, json, sarif, cyclonedx or none.</error>', (string) $input->getOption('format')));

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
        if ((bool) $input->getOption('offline')) {
            // The Composer instance (and its HttpDownloader, which reads this variable when constructed)
            // may already exist when a plugin command runs; discard it so a fresh, network-less one is built.
            Platform::putEnv('COMPOSER_DISABLE_NETWORK', '1');
            $this->resetComposer();
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
        $dbOption = $input->getOption('database-location');
        $locator = new DatabaseLocator($composer, Factory::createHttpDownloader($io, $composer->getConfig()), (bool) $input->getOption('offline'));
        $dbLocation = $locator->configured(is_string($dbOption) ? $dbOption : null);
        if (is_string($advisoriesFile) && $advisoriesFile !== '') {
            $advisories = new JsonFileAdvisoryProvider($advisoriesFile);
        } elseif ($dbLocation !== null) {
            try {
                $advisories = new SqliteAdvisoryProvider(Database::open($locator->resolve($dbLocation)));
            } catch (AdvisoryLookupFailed $e) {
                $io->writeError('<error>Advisory database unavailable: ' . $e->getMessage() . '</error>');

                return Plan::EXIT_ADVISORIES_UNAVAILABLE;
            }
        } else {
            $advisories = ComposerRepositoryAdvisoryProvider::fromRepositoryManager($composer->getRepositoryManager());
        }

        $solver = new InProcessSolver($this->getPlatformRequirementFilter($input));
        $maxCandidates = max(1, (int) $input->getOption('max-candidates'));
        $ignored = array_values(array_filter(array_map('strval', (array) $input->getOption('ignore')), static fn (string $v): bool => $v !== ''));
        array_push($ignored, ...self::configuredIgnores($composer->getConfig()));
        $planner = new Planner(
            $advisories,
            $solver,
            new CandidateGenerator(allowDirectRequire: (bool) $input->getOption('allow-direct-require')),
            !(bool) $input->getOption('no-dev'),
            $maxCandidates,
            static function (string $message) use ($io): void {
                $io->writeError('<comment>' . $message . '</comment>', true, \Composer\IO\IOInterface::VERBOSE);
            },
            $ignored,
        );

        try {
            $plan = $planner->plan($context, ScratchWorkspace::fromProject($context));
        } catch (AdvisoryLookupFailed $e) {
            $io->writeError('<error>Advisory data unavailable: ' . $e->getMessage() . '</error>');
            if ((bool) $input->getOption('offline')) {
                $io->writeError('<comment>Offline mode: pass --advisories-file=<json> or --database-location=<sqlite> (see remediate:db-build).</comment>');
            }

            return Plan::EXIT_ADVISORIES_UNAVAILABLE;
        }

        $failOn = $input->getOption('fail-on');
        if (is_string($failOn) && $failOn !== '') {
            try {
                $plan = $plan->withFailOn($failOn);
            } catch (\InvalidArgumentException $e) {
                $io->writeError('<error>' . $e->getMessage() . '</error>');

                return Plan::EXIT_ERROR;
            }
        }

        $minimal = $solver->supportsMinimalChanges();
        $lockLines = LockLineIndex::fromFile($context->lockPath());
        foreach ($outputs as [$fileFormat, $path]) {
            if ($path === null || $fileFormat === ReportFormat::None) {
                continue;
            }
            if (@file_put_contents($path, $fileFormat->render($plan, $minimal, false, $lockLines)) === false) {
                $io->writeError(sprintf('<error>Could not write %s report to %s</error>', $fileFormat->value, $path));

                return Plan::EXIT_ERROR;
            }
            $io->writeError(sprintf('%s report written to %s', ucfirst($fileFormat->value), $path));
        }
        if ($format !== ReportFormat::None) {
            $decorated = $format === ReportFormat::Text && $output->isDecorated();
            $output->write($format->render($plan, $minimal, $decorated, $lockLines), false, $decorated ? OutputInterface::OUTPUT_NORMAL : OutputInterface::OUTPUT_RAW);
        }

        return $plan->exitCode();
    }
}
