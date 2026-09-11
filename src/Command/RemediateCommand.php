<?php

declare(strict_types=1);

namespace Remediate\Command;

use Composer\Command\BaseCommand;
use Composer\Factory;
use Composer\IO\IOInterface;
use Composer\Util\Platform;
use Remediate\Engine\Advisory\AdvisoryLookupFailed;
use Remediate\Engine\Advisory\AdvisoryProvider;
use Remediate\Engine\Advisory\AuditSubprocessAdvisoryProvider;
use Remediate\Engine\Advisory\ComposerRepositoryAdvisoryProvider;
use Remediate\Engine\Advisory\Db\Database;
use Remediate\Engine\Advisory\Db\DatabaseBuildFactory;
use Remediate\Engine\Advisory\Db\DatabaseLocator;
use Remediate\Engine\Advisory\Db\OperatorConfiguration;
use Remediate\Engine\Advisory\Db\SqliteAdvisoryProvider;
use Remediate\Engine\Advisory\FallbackAdvisoryProvider;
use Remediate\Engine\Advisory\JsonFileAdvisoryProvider;
use Remediate\Engine\Candidate\CandidateGenerator;
use Remediate\Engine\Matching\IgnorePolicy;
use Remediate\Engine\Plan\BaselineFile;
use Remediate\Engine\Plan\Plan;
use Remediate\Engine\Planner;
use Remediate\Engine\Project\ProjectContext;
use Remediate\Engine\Solver\FallbackSolver;
use Remediate\Engine\Solver\InProcessSolver;
use Remediate\Engine\Solver\ReleaseAgeGuard;
use Remediate\Engine\Solver\ScratchWorkspace;
use Remediate\Engine\Solver\SolverInterface;
use Remediate\Engine\Solver\SubprocessSolver;
use Remediate\Output\ConsoleText;
use Remediate\Output\LockLineIndex;
use Remediate\Output\ReportFormat;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

final class RemediateCommand extends BaseCommand
{
    public const SOLVERS = ['auto', 'in-process', 'subprocess'];

    /** @var list<string> warnings gathered while choosing the advisory source, attached to the plan */
    private array $planWarnings = [];

    /** Composer's configuration as the operator gave it, without the analysed project's contribution. */
    private readonly OperatorConfiguration $operator;

    public function __construct(?OperatorConfiguration $operator = null)
    {
        $this->operator = $operator ?? new OperatorConfiguration();
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->setName('remediate')
            ->setDescription('Find the least invasive Composer-verified upgrade that removes each known vulnerability from composer.lock')
            ->setDefinition([
                new InputOption('format', 'f', InputOption::VALUE_REQUIRED, 'Format printed to standard output: text, html, json, sarif, cyclonedx, gitlab or none', 'text'),
                new InputOption('output', 'o', InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY, 'Also write a report file; format inferred from the name (.html, .json, .sarif, .cdx.json, gl-dependency-scanning-report.json, .txt) or given as sarif:path. Repeatable.'),
                new InputOption('fail-on', null, InputOption::VALUE_REQUIRED, 'Only findings at or above this severity (low, medium, high, critical) affect the exit code; findings of unknown severity always count'),
                new InputOption('baseline', null, InputOption::VALUE_REQUIRED, 'Baseline file of accepted findings; findings listed there are reported but do not affect the exit code'),
                new InputOption('update-baseline', null, InputOption::VALUE_NONE, 'Write every finding of this run to the --baseline file (accept the current state, then tighten over time)'),
                new InputOption('min-release-age', null, InputOption::VALUE_REQUIRED, 'Never recommend a release published fewer than this many days ago, or without a known release date (supply-chain cooldown)'),
                new InputOption('no-dev', null, InputOption::VALUE_NONE, 'Ignore vulnerabilities in require-dev packages'),
                new InputOption('offline', null, InputOption::VALUE_NONE, 'Refuse all network access; needs a warm Composer cache plus an advisory database already at its path, or --advisories-file (sets COMPOSER_DISABLE_NETWORK=1)'),
                new InputOption('ignore', 'i', InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY, 'Advisory id or CVE to ignore (repeatable); audit-scoped entries of config.audit.ignore and config.policy.advisories are honoured as well'),
                new InputOption('no-project-ignores', null, InputOption::VALUE_NONE, 'Leave out the ignore entries the analysed project\'s own composer.json carries (config.audit.ignore, config.policy.advisories), so that a repository cannot suppress its own findings; your --ignore entries still apply'),
                new InputOption('allow-direct-require', null, InputOption::VALUE_NONE, 'Also consider adding a transitive package as a direct requirement to force a fixed version'),
                new InputOption('advisories-file', null, InputOption::VALUE_REQUIRED, 'Read advisories from a JSON file in the Packagist API shape (or `composer audit --format=json` output) instead of the configured repositories'),
                new InputOption('database-location', null, InputOption::VALUE_REQUIRED, 'Where the advisory database comes from: https URL(s) of a published database, comma-separated and tried in order (default: the database this project publishes); `composer` to ask the configured repositories instead; or a local file to read as it is. Also REMEDIATE_DATABASE or extra.remediate.database'),
                new InputOption('database-path', null, InputOption::VALUE_REQUIRED, 'The file the advisory database is kept in and read from (default: COMPOSER_CACHE_DIR/remediate/advisories.sqlite); also REMEDIATE_DATABASE_PATH or extra.remediate.database_path. Cache it between CI runs'),
                new InputOption('database-max-age', null, InputOption::VALUE_REQUIRED, 'When the database cannot be confirmed current (source unreachable, --offline), fail with exit 4 instead of warning if the copy is older than this many hours (or 2d, 36h); also REMEDIATE_DATABASE_MAX_AGE or extra.remediate.database_max_age'),
                new InputOption('no-database', null, InputOption::VALUE_NONE, 'Ask the configured repositories for advisories, as composer audit does, instead of using an advisory database (same as --database-location=composer)'),
                new InputOption('rebuild-database', null, InputOption::VALUE_NONE, 'When the database at its path is missing or not current, build it from the sources (Packagist, OSV, FriendsOfPHP, with EPSS and KEV data) instead of downloading it'),
                new InputOption('database-sha256', null, InputOption::VALUE_REQUIRED, 'Expected sha256 of the advisory database (hex); a downloaded or cached copy that differs is refused. The trust anchor for a URL you do not publish yourself'),
                new InputOption('allow-unverified-database', null, InputOption::VALUE_NONE, 'Accept a database URL without a published <url>.sha256 sidecar and without --database-sha256 (refused otherwise); the report says the download was not verified'),
                new InputOption('accept-coverage-gaps', null, InputOption::VALUE_NONE, 'Exit 0 for a lock without findings even when the advisory source could not read records about locked packages (otherwise exit 4), and allow a fix that adds a package with such records (otherwise rejected); the gaps stay in the report'),
                new InputOption('max-candidates', null, InputOption::VALUE_REQUIRED, 'Maximum number of candidate commands to try per finding', '10'),
                new InputOption('solve-budget', null, InputOption::VALUE_REQUIRED, 'Maximum number of solver runs per finding, all search phases included (candidates, conflict expansion, parent descent, simplification)', (string) Planner::DEFAULT_SOLVE_BUDGET),
                new InputOption('solver', null, InputOption::VALUE_REQUIRED, 'How candidates are verified: auto (in-process, falling back to a `composer update` subprocess when the in-process route errors), in-process, or subprocess', 'auto'),
                new InputOption('ignore-platform-req', null, InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY, 'Ignore a specific platform requirement (php & ext- packages) when validating candidates; the flag is repeated in the recommended command'),
                new InputOption('ignore-platform-reqs', null, InputOption::VALUE_NONE, 'Ignore all platform requirements when validating candidates; the flag is repeated in the recommended command'),
            ])
            ->setHelp(<<<'HELP'
Reads composer.json and composer.lock, matches the locked packages against security advisories,
and for every finding tries a series of <info>composer update</info> commands in a dry-run, from
least to most invasive. Only commands whose resulting lock file no longer contains the
vulnerability are recommended. Nothing in the project is modified.

Exit codes: 0 no vulnerabilities, 1 vulnerabilities with a verified remediation,
2 at least one vulnerability without a verified remediation (and no tool failure), 3 error (also
when a solver error prevented the search from completing), 4 advisory data unavailable (also when
the source could not read records about locked packages and <info>--accept-coverage-gaps</info> was
not given), 5 package metadata could not be fetched while solving.

Advisories come from an advisory database kept at <info>--database-path</info> (default: Composer's
cache directory). On every run the file is checked against the published database it comes from
(<info>--database-location</info>, default: this project's release): a copy with the same sha256 or
dataset hash, or a newer local build, is used; a missing or stale copy is downloaded (or rebuilt with
<info>--rebuild-database</info>); when the source cannot be reached the copy is used and the report says
how old it is. Without any usable database the configured repositories are asked, as
<info>composer audit</info> does, and the report says so. <info>--no-database</info> chooses that directly.

Running as <info>composer remediate</info> means Composer has already activated the project's
other allowed plugins before this command starts. The <info>composer-remediate</info> binary shipped
with the package runs the same command with plugins and scripts disabled from the first instruction.
HELP);
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = $this->getIO();
        $targets = $this->reportTargets($input, $io);
        if (is_int($targets)) {
            return $targets;
        }
        [$format, $files] = $targets;
        $error = $this->checkRuntime($input, $io);
        if ($error !== null) {
            return $error;
        }
        $composer = $this->requireComposer();
        $context = ProjectContext::fromComposer($composer);
        if (!$context->isLocked()) {
            $io->writeError('<error>No composer.lock found. Run composer install or composer update first.</error>');

            return Plan::EXIT_ERROR;
        }
        $locator = $this->databaseLocator($input, $composer, $io);
        if (is_int($locator)) {
            return $locator;
        }
        $advisories = $this->advisoryProvider($input, $composer, $context, $locator, $io);
        if (is_int($advisories)) {
            return $advisories;
        }
        $this->planWarnings = [...$locator->warnings(), ...$this->planWarnings];
        $platformArguments = self::platformArguments($input);
        $solver = $this->buildSolver(strtolower((string) $input->getOption('solver')), $input, $platformArguments);

        try {
            $plan = $this->planner($input, $advisories, $solver, $platformArguments, $io)->plan($context, ScratchWorkspace::fromProject($context));
        } catch (AdvisoryLookupFailed $e) {
            $io->writeError('<error>Advisory data unavailable: ' . ConsoleText::safe($e->getMessage()) . '</error>');
            if ((bool) $input->getOption('offline')) {
                $io->writeError('<comment>Offline mode: the advisory database must already be at its path (see remediate:db-status), or pass --advisories-file=<json>.</comment>');
            }

            return Plan::EXIT_ADVISORIES_UNAVAILABLE;
        }
        $plan = $plan->withWarnings([...$this->planWarnings, ...($advisories instanceof FallbackAdvisoryProvider ? $advisories->warnings() : [])]);
        $plan = $this->gate($plan, $input, $io);
        if (is_int($plan)) {
            return $plan;
        }

        return $this->emit($plan, $format, $files, $solver->supportsMinimalChanges(), LockLineIndex::fromFile($context->lockPath()), $output, $io);
    }

    /**
     * The --format choice and the --output files, or an exit code when either is malformed.
     *
     * @return array{ReportFormat, list<array{ReportFormat, ?string}>}|int
     */
    private function reportTargets(InputInterface $input, IOInterface $io): array|int
    {
        $format = ReportFormat::tryFrom(strtolower((string) $input->getOption('format')));
        if ($format === null) {
            $io->writeError(sprintf('<error>Unknown format "%s"; use text, html, json, sarif, cyclonedx, gitlab or none.</error>', (string) $input->getOption('format')));

            return Plan::EXIT_ERROR;
        }
        $files = [];
        foreach ((array) $input->getOption('output') as $spec) {
            if (!is_string($spec) || $spec === '') {
                continue;
            }
            try {
                $files[] = ReportFormat::parseOutputSpec($spec);
            } catch (\InvalidArgumentException $e) {
                $io->writeError('<error>' . ConsoleText::safe($e->getMessage()) . '</error>');

                return Plan::EXIT_ERROR;
            }
        }

        return [$format, $files];
    }

    /**
     * Option and environment checks that need no project: solver choice, cooldown, Composer version,
     * offline mode, PHP end of life. An exit code when the run cannot proceed.
     */
    private function checkRuntime(InputInterface $input, IOInterface $io): ?int
    {
        $solverChoice = strtolower((string) $input->getOption('solver'));
        if (!in_array($solverChoice, self::SOLVERS, true)) {
            $io->writeError(sprintf('<error>Unknown solver "%s"; use auto, in-process or subprocess.</error>', $solverChoice));

            return Plan::EXIT_ERROR;
        }
        $minAge = $input->getOption('min-release-age');
        if (is_string($minAge) && $minAge !== '' && !ctype_digit($minAge)) {
            $io->writeError(sprintf('<error>--min-release-age must be a whole number of days, got "%s".</error>', $minAge));

            return Plan::EXIT_ERROR;
        }
        // composer audit, transitive --with and the advisory API all appeared in Composer 2.4.
        if (!class_exists(\Composer\Advisory\Auditor::class)) {
            $io->writeError(sprintf('<error>composer remediate needs Composer 2.4 or newer; this is Composer %s.</error>', \Composer\Composer::getVersion()));

            return Plan::EXIT_ERROR;
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

        return null;
    }

    /** The locator for a shared advisory database, honouring --offline, --database-sha256 and --allow-unverified-database. */
    private function databaseLocator(InputInterface $input, \Composer\Composer $composer, IOInterface $io): DatabaseLocator|int
    {
        $expectedSha = $input->getOption('database-sha256');
        if (is_string($expectedSha) && $expectedSha !== '' && preg_match('{^[0-9a-f]{64}$}i', $expectedSha) !== 1) {
            $io->writeError('<error>--database-sha256 must be a 64-character hexadecimal sha256 digest.</error>');

            return Plan::EXIT_ERROR;
        }

        return new DatabaseLocator($composer, $this->operator->httpDownloader($io), (bool) $input->getOption('offline'), !(bool) $input->getOption('allow-unverified-database'), is_string($expectedSha) && $expectedSha !== '' ? strtolower($expectedSha) : null, $this->operator);
    }

    /**
     * Where advisories come from, in order of preference: --advisories-file; the advisory database at its
     * path, kept current from the configured sources (or rebuilt with --rebuild-database); else Composer's
     * own repositories, with a warning when a database was expected but none could be had. Exit 4 for a
     * database that is refused (digest mismatch, unverifiable download, too old) or a pinned digest that
     * nothing satisfies.
     */
    private function advisoryProvider(InputInterface $input, \Composer\Composer $composer, ProjectContext $context, DatabaseLocator $locator, IOInterface $io): AdvisoryProvider|int
    {
        $advisoriesFile = $input->getOption('advisories-file');
        if (is_string($advisoriesFile) && $advisoriesFile !== '') {
            return new JsonFileAdvisoryProvider($advisoriesFile);
        }
        $option = static fn (string $name): ?string => is_string($v = $input->getOption($name)) && $v !== '' ? $v : null;
        try {
            $settings = $locator->settings($option('database-location'), $option('database-path'), $option('database-max-age'), (bool) $input->getOption('no-database'), $context->directory);
        } catch (\InvalidArgumentException $e) {
            $io->writeError('<error>' . ConsoleText::safe($e->getMessage()) . '</error>');

            return Plan::EXIT_ERROR;
        }
        if (!$settings->usesDatabase()) {
            return self::composerAdvisoryProvider($composer, $context);
        }
        $rebuild = null;
        if ((bool) $input->getOption('rebuild-database')) {
            $downloader = $this->operator->httpDownloader($io);
            $tempDir = $locator->cacheDirectory() . '/tmp';
            $rebuild = static function (string $path) use ($downloader, $tempDir, $io): void {
                $io->writeError('<comment>Building the advisory database from the sources…</comment>');
                DatabaseBuildFactory::defaultBuilder($downloader, $tempDir)->build($path, static function (string $message) use ($io): void {
                    $io->writeError('<comment>' . ConsoleText::safe($message) . '</comment>', true, IOInterface::VERBOSE);
                }, ['engine_version' => Planner::engineVersion()]);
            };
        }
        try {
            $located = $locator->locate($settings, $rebuild);
            if ($located !== null) {
                return new SqliteAdvisoryProvider(Database::open($located->path), $located->provenance);
            }
        } catch (AdvisoryLookupFailed $e) {
            $io->writeError('<error>Advisory database unavailable: ' . ConsoleText::safe($e->getMessage()) . '</error>');

            return Plan::EXIT_ADVISORIES_UNAVAILABLE;
        }
        $why = $locator->warnings() === [] ? 'no advisory database' : $locator->warnings()[count($locator->warnings()) - 1];
        if ($option('database-sha256') !== null) {
            $io->writeError('<error>Advisory database unavailable and --database-sha256 was given, so no other source is acceptable: ' . ConsoleText::safe($why) . '</error>');

            return Plan::EXIT_ADVISORIES_UNAVAILABLE;
        }
        $this->planWarnings[] = 'Advisory database unavailable; the configured repositories were asked instead, as composer audit does. Exploit data and coverage gaps are not available from that source.';
        foreach ($locator->warnings() as $warning) {
            $io->writeError('<comment>' . ConsoleText::safe($warning) . ($warning === $why ? ' Asking the configured repositories instead.' : '') . '</comment>');
        }

        return self::composerAdvisoryProvider($composer, $context);
    }

    /**
     * @param list<string> $platformArguments
     */
    private function planner(InputInterface $input, AdvisoryProvider $advisories, SolverInterface $solver, array $platformArguments, IOInterface $io): Planner
    {
        $minAge = $input->getOption('min-release-age');
        $cliIgnores = array_values(array_filter(array_map('strval', (array) $input->getOption('ignore')), static fn (string $v): bool => $v !== ''));

        return new Planner(
            $advisories,
            $solver,
            new CandidateGenerator(allowDirectRequire: (bool) $input->getOption('allow-direct-require'), extraArguments: $platformArguments),
            !(bool) $input->getOption('no-dev'),
            max(1, (int) $input->getOption('max-candidates')),
            static function (string $message) use ($io): void {
                $io->writeError('<comment>' . ConsoleText::safe($message) . '</comment>', true, IOInterface::VERBOSE);
            },
            $this->ignorePolicy($input, $io)->withIds($cliIgnores),
            is_string($minAge) && $minAge !== '' ? new ReleaseAgeGuard((int) $minAge) : null,
            max(1, (int) $input->getOption('solve-budget')),
            (bool) $input->getOption('accept-coverage-gaps'),
        );
    }

    /**
     * Which advisories to leave out. The analysed project's `config.audit.ignore` and
     * `config.policy.advisories` suppress findings, which is their purpose for a project you own; the
     * entries are attributed to the project in the report, and --no-project-ignores leaves them out for
     * a repository whose word you do not take.
     */
    private function ignorePolicy(InputInterface $input, IOInterface $io): IgnorePolicy
    {
        $config = $this->requireComposer()->getConfig();
        $fromProject = $this->operator->keysSetByProject($config, ['audit', 'policy']);
        if (!(bool) $input->getOption('no-project-ignores')) {
            return IgnorePolicy::fromComposerConfig($config, $fromProject);
        }
        $policy = IgnorePolicy::fromComposerConfig($config, $fromProject);
        if ($policy->projectEntries() !== []) {
            $this->planWarnings[] = sprintf('The analysed project\'s composer.json suppresses advisories (%s); --no-project-ignores left those entries out of this run.', implode(', ', $policy->projectEntries()));
            $io->writeError('<comment>' . ConsoleText::safe('--no-project-ignores: ignoring the project\'s own ignore entries (' . implode(', ', $policy->projectEntries()) . ').') . '</comment>');
        }

        return IgnorePolicy::none();
    }

    /** Applies --accept-coverage-gaps, --fail-on and the baseline options to the plan; an exit code when they are malformed. */
    private function gate(Plan $plan, InputInterface $input, IOInterface $io): Plan|int
    {
        if ((bool) $input->getOption('accept-coverage-gaps')) {
            $plan = $plan->withAcceptedCoverageGaps();
        }
        $failOn = $input->getOption('fail-on');
        if (is_string($failOn) && $failOn !== '') {
            try {
                $plan = $plan->withFailOn($failOn);
            } catch (\InvalidArgumentException $e) {
                $io->writeError('<error>' . ConsoleText::safe($e->getMessage()) . '</error>');

                return Plan::EXIT_ERROR;
            }
        }
        $baselinePath = $input->getOption('baseline');
        if (!is_string($baselinePath) || $baselinePath === '') {
            if ((bool) $input->getOption('update-baseline')) {
                $io->writeError('<error>--update-baseline needs --baseline=<file>.</error>');

                return Plan::EXIT_ERROR;
            }

            return $plan;
        }
        try {
            if ((bool) $input->getOption('update-baseline')) {
                BaselineFile::write($baselinePath, $plan);
                $io->writeError(sprintf('Baseline written to %s (%d finding%s accepted).', $baselinePath, count($plan->findingKeys()), count($plan->findingKeys()) === 1 ? '' : 's'));
            }
            if (is_file($baselinePath)) {
                return $plan->withBaseline(BaselineFile::read($baselinePath));
            }
            $io->writeError(sprintf('<warning>Baseline %s does not exist; run with --update-baseline to create it.</warning>', $baselinePath));
        } catch (\RuntimeException $e) {
            $io->writeError('<error>' . ConsoleText::safe($e->getMessage()) . '</error>');

            return Plan::EXIT_ERROR;
        }

        return $plan;
    }

    /**
     * Writes the --output files and the --format report to standard output; the exit code is the plan's.
     *
     * @param list<array{ReportFormat, ?string}> $files
     */
    private function emit(Plan $plan, ReportFormat $format, array $files, bool $minimal, LockLineIndex $lockLines, OutputInterface $output, IOInterface $io): int
    {
        foreach ($files as [$fileFormat, $path]) {
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

    /**
     * Advisories from the configured repositories through Composer's in-process advisory API, with
     * `composer audit --locked` as the fallback when that @internal API is missing or breaks at
     * runtime (see docs/design-decisions.md). Composer older than 2.4 has neither and is rejected
     * before this point.
     */
    private static function composerAdvisoryProvider(\Composer\Composer $composer, ProjectContext $context): AdvisoryProvider
    {
        $audit = new AuditSubprocessAdvisoryProvider($context->directory, SubprocessSolver::forRunningComposer()->composerCommand());
        if (!interface_exists(\Composer\Repository\AdvisoryProviderInterface::class)) {
            return $audit;
        }

        return new FallbackAdvisoryProvider(ComposerRepositoryAdvisoryProvider::fromRepositoryManager($composer->getRepositoryManager()), $audit);
    }

    /**
     * The platform flags as the user must repeat them: a candidate verified with PHP requirements
     * ignored is only reproduced by a command that ignores them too.
     *
     * @return list<string>
     */
    private static function platformArguments(InputInterface $input): array
    {
        if ((bool) $input->getOption('ignore-platform-reqs')) {
            return ['--ignore-platform-reqs'];
        }
        $arguments = [];
        foreach ((array) $input->getOption('ignore-platform-req') as $req) {
            if (is_string($req) && $req !== '') {
                $arguments[] = '--ignore-platform-req=' . $req;
            }
        }

        return $arguments;
    }

    /** @param list<string> $platformArguments */
    private function buildSolver(string $choice, InputInterface $input, array $platformArguments): SolverInterface
    {
        $inProcess = new InProcessSolver($this->getPlatformRequirementFilter($input));
        if ($choice === 'in-process') {
            return $inProcess;
        }
        $subprocess = SubprocessSolver::forRunningComposer();
        if ($choice === 'subprocess') {
            return $subprocess;
        }

        return new FallbackSolver($inProcess, $subprocess);
    }
}
