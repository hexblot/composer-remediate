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
use Remediate\Engine\Apply\Applier;
use Remediate\Engine\Apply\ApplyOutcome;
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
                new InputOption('exposed', null, InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY, 'Package that handles untrusted input in this application (repeatable): its production findings are listed first. Changes the order of the report only, never a recommendation or the exit code'),
                new InputOption('baseline', null, InputOption::VALUE_REQUIRED, 'Baseline file of accepted findings; findings listed there are reported but do not affect the exit code'),
                new InputOption('update-baseline', null, InputOption::VALUE_NONE, 'Write every finding of this run to the --baseline file (accept the current state, then tighten over time)'),
                new InputOption('min-release-age', null, InputOption::VALUE_REQUIRED, 'Never recommend a release published fewer than this many days ago, or without a known release date (supply-chain cooldown)'),
                new InputOption('no-dev', null, InputOption::VALUE_NONE, 'Ignore vulnerabilities in require-dev packages'),
                new InputOption('offline', null, InputOption::VALUE_NONE, 'Refuse all network access; needs a warm Composer cache plus an advisory database already at its path, or --advisories-file (sets COMPOSER_DISABLE_NETWORK=1)'),
                new InputOption('ignore', 'i', InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY, 'Advisory id or CVE to ignore (repeatable); audit-scoped entries of config.audit.ignore and config.policy.advisories are honoured as well'),
                new InputOption('apply', null, InputOption::VALUE_NONE, 'Run the recommended command in this project instead of only printing it, then report the state it leaves behind. The composer.json and composer.lock from before the run are copied outside the project first and the report says where'),
                new InputOption('apply-root-constraints', null, InputOption::VALUE_NONE, 'Let --apply run a recommendation that edits composer.json (a widened root constraint), which it refuses to do on its own'),
                new InputOption('apply-no-install', null, InputOption::VALUE_NONE, 'With --apply, write composer.lock and leave vendor/ alone (adds --no-install to the update), for a workflow that commits the lock rather than running the project'),
                new InputOption('apply-allow-dirty', null, InputOption::VALUE_NONE, 'Let --apply run although composer.json or composer.lock are already modified in this git checkout, mixing its changes into yours'),
                new InputOption('no-project-ignores', null, InputOption::VALUE_NONE, 'Leave out the ignore entries the analysed project\'s own composer.json carries (config.audit.ignore, config.policy.advisories), so that a repository cannot suppress its own findings; your --ignore entries still apply'),
                new InputOption('allow-direct-require', null, InputOption::VALUE_NONE, 'Also consider adding a transitive package as a direct requirement to force a fixed version'),
                new InputOption('advisories-file', null, InputOption::VALUE_REQUIRED, 'Read advisories from a JSON file in the Packagist API shape (or `composer audit --format=json` output) instead of the configured repositories'),
                new InputOption('database-location', null, InputOption::VALUE_REQUIRED, 'Where the advisory database comes from: https URL(s) of a published database, comma-separated and tried in order (default: the database this project publishes); `composer` to ask the configured repositories instead; or a local file to read as it is. Also REMEDIATE_DATABASE or extra.remediate.database'),
                new InputOption('database-path', null, InputOption::VALUE_REQUIRED, 'The file the advisory database is kept in and read from (default: COMPOSER_CACHE_DIR/remediate/advisories.sqlite); also REMEDIATE_DATABASE_PATH or extra.remediate.database_path. Cache it between CI runs'),
                new InputOption('database-max-age', null, InputOption::VALUE_REQUIRED, 'When the database cannot be confirmed current (source unreachable, --offline), fail with exit 4 instead of warning if the copy is older than this many hours (or 2d, 36h); also REMEDIATE_DATABASE_MAX_AGE or extra.remediate.database_max_age'),
                new InputOption('no-database', null, InputOption::VALUE_NONE, 'Ask the configured repositories for advisories, as composer audit does, instead of using an advisory database (same as --database-location=composer)'),
                new InputOption('rebuild-database', null, InputOption::VALUE_NONE, 'When the database at its path is missing or not current, build it from the sources (Packagist, OSV, FriendsOfPHP, Drupal.org, with EPSS and KEV data) instead of downloading it'),
                new InputOption('database-sha256', null, InputOption::VALUE_REQUIRED, 'Expected sha256 of the advisory database (hex); a downloaded or cached copy that differs is refused. The trust anchor for a URL you do not publish yourself'),
                new InputOption('allow-unverified-database', null, InputOption::VALUE_NONE, 'Accept a database URL without a published <url>.sha256 sidecar and without --database-sha256 (refused otherwise); the report says the download was not verified'),
                new InputOption('accept-coverage-gaps', null, InputOption::VALUE_NONE, 'Exit 0 for a lock without findings even when the advisory source could not read records about locked packages (otherwise exit 4), and allow a fix that adds a package with such records (otherwise rejected); the gaps stay in the report'),
                new InputOption('max-candidates', null, InputOption::VALUE_REQUIRED, 'Maximum number of candidate commands to try per finding', '10'),
                new InputOption('solve-budget', null, InputOption::VALUE_REQUIRED, 'Maximum number of solver runs per finding, all search phases included (candidates, conflict expansion, parent descent, simplification)', (string) Planner::DEFAULT_SOLVE_BUDGET),
                new InputOption('parallelize', 'p', InputOption::VALUE_REQUIRED, 'Plan this many packages at once in forked worker processes (default 1, one after another). Each worker runs its own Composer solves, so allow a few hundred MB of memory per worker; `auto` uses the number of processor cores, at most 4', '1'),
                new InputOption('solver', null, InputOption::VALUE_REQUIRED, 'How candidates are verified: auto (in-process, falling back to a `composer update` subprocess when the in-process route errors), in-process, or subprocess', 'auto'),
                new InputOption('ignore-platform-req', null, InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY, 'Ignore a specific platform requirement (php & ext- packages) when validating candidates; the flag is repeated in the recommended command'),
                new InputOption('ignore-platform-reqs', null, InputOption::VALUE_NONE, 'Ignore all platform requirements when validating candidates; the flag is repeated in the recommended command'),
            ])
            ->setHelp(<<<'HELP'
Reads composer.json and composer.lock, matches the locked packages against security advisories,
and for every finding tries a series of <info>composer update</info> commands in a dry-run, from
least to most invasive. Only commands whose resulting lock file no longer contains the
vulnerability are recommended. Nothing in the project is modified.

<info>--apply</info> runs the recommended command here rather than printing it for you to run, and then
plans again, so what the report shows is the state the run left behind and not a prediction of it. It
copies composer.json and composer.lock outside the project first and says where. It refuses when there
is no verified command, when the recommendation would edit composer.json (pass
<info>--apply-root-constraints</info>), when those files changed while the plan was being computed, and
when they are already modified in a git checkout (pass <info>--apply-allow-dirty</info>). Everything
else the tool does leaves your project untouched.

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

        try {
            return $this->scan($input, $output, $io, $format, $files);
        } catch (\Throwable $e) {
            // Nothing may leave this command without its reports being written. An exception used to
            // escape to Symfony, which reports it and exits 1 — the code that means "vulnerabilities,
            // every one with a verified fix". A broken advisory database reached a pipeline that way:
            // exit 1, no report written, the previous successful one still on disk, and the shipped
            // action carrying on to open a pull request.
            $io->writeError('<error>' . ConsoleText::safe($e->getMessage()) . '</error>');

            return $this->emitFailure(Plan::EXIT_ERROR, $format, $files, $output, $io, null, sprintf('%s: %s', (new \ReflectionClass($e))->getShortName(), $e->getMessage()));
        }
    }

    /**
     * The run itself. Every exit from here is either a report or an exit code that execute() turns into
     * one.
     *
     * @param list<array{ReportFormat, ?string}> $files
     */
    private function scan(InputInterface $input, OutputInterface $output, IOInterface $io, ReportFormat $format, array $files): int
    {
        $error = $this->checkRuntime($input, $io);
        if ($error !== null) {
            return $this->emitFailure($error, $format, $files, $output, $io);
        }
        $composer = $this->requireComposer();
        $context = ProjectContext::fromComposer($composer);
        if (!$context->isLocked()) {
            $io->writeError('<error>No composer.lock found. Run composer install or composer update first.</error>');

            return $this->emitFailure(Plan::EXIT_ERROR, $format, $files, $output, $io);
        }
        $locator = $this->databaseLocator($input, $composer, $io);
        if (is_int($locator)) {
            return $this->emitFailure($locator, $format, $files, $output, $io, $context->lockPath());
        }
        $advisories = $this->advisoryProvider($input, $composer, $context, $locator, $io);
        if (is_int($advisories)) {
            return $this->emitFailure($advisories, $format, $files, $output, $io, $context->lockPath());
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

            return $this->emitFailure(Plan::EXIT_ADVISORIES_UNAVAILABLE, $format, $files, $output, $io, $context->lockPath(), 'Advisory data unavailable: ' . $e->getMessage());
        }
        $plan = $plan->withWarnings([...$this->planWarnings, ...($advisories instanceof FallbackAdvisoryProvider ? $advisories->warnings() : [])]);
        $plan = $this->gate($plan, $input, $io);
        if (is_int($plan)) {
            return $this->emitFailure($plan, $format, $files, $output, $io, $context->lockPath());
        }

        if ((bool) $input->getOption('apply')) {
            $applied = $this->applyPlan($plan, $context, $advisories, $solver, $platformArguments, $input, $io);
            if (is_int($applied)) {
                return $this->emitFailure($applied, $format, $files, $output, $io, $context->lockPath());
            }
            $plan = $applied;
            $context = ProjectContext::fromComposer($this->requireComposer());
        }

        return $this->emit($plan, $format, $files, $solver->supportsMinimalChanges(), LockLineIndex::fromFile($context->lockPath()), $output, $io);
    }

    /**
     * Writes the declared reports for a run that could not answer, and returns its exit code.
     *
     * Eighth adversarial review, finding 3. A failure used to return before anything was rendered, so
     * `--output=scan.sarif` kept whatever the last successful run had written: a CI step uploading that
     * file published a clean result, `executionSuccessful` and all, for a scan that never ran. A report
     * that is not written is not a report that is absent; it is the previous one, still read as this
     * one's.
     *
     * The plan carries the failure, so ScanOutcome makes every format say the run did not complete
     * rather than show an empty vulnerability list.
     *
     * @param list<array{ReportFormat, ?string}> $files
     */
    private function emitFailure(int $exitCode, ReportFormat $format, array $files, OutputInterface $output, IOInterface $io, ?string $lockPath = null, ?string $reason = null): int
    {
        $warnings = $this->planWarnings;
        if ($reason !== null && $reason !== '') {
            $warnings[] = $reason;
        }
        $plan = Plan::failed($exitCode, ['engine_version' => Planner::engineVersion(), 'analysis_timestamp' => gmdate('c')], $warnings);
        $emitted = $this->emit($plan, $format, $files, true, $lockPath !== null ? LockLineIndex::fromFile($lockPath) : LockLineIndex::empty(), $output, $io);

        return $emitted === Plan::EXIT_ERROR ? Plan::EXIT_ERROR : $exitCode;
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

        return new DatabaseLocator($composer, $this->operator->httpDownloader(), (bool) $input->getOption('offline'), !(bool) $input->getOption('allow-unverified-database'), is_string($expectedSha) && $expectedSha !== '' ? strtolower($expectedSha) : null, $this->operator);
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
        $option = static fn (string $name): ?string => is_string($v = $input->getOption($name)) && $v !== '' ? $v : null;
        $advisoriesFile = $input->getOption('advisories-file');
        if (is_string($advisoriesFile) && $advisoriesFile !== '') {
            // A pinned digest says the operator will accept that database and nothing else. Reading
            // advisories from somewhere else instead is not a different way of honouring that, it is
            // ignoring it: the pin would go unchecked and a file naming no advisories would report the
            // lock clean. The two cannot both be meant, so the run stops rather than choosing one.
            if ($option('database-sha256') !== null) {
                $io->writeError('<error>--database-sha256 pins the advisory database, so --advisories-file cannot be used in the same run: it would read advisories from somewhere the pin does not cover.</error>');

                return Plan::EXIT_ADVISORIES_UNAVAILABLE;
            }

            return new JsonFileAdvisoryProvider($advisoriesFile);
        }
        try {
            $settings = $locator->settings($option('database-location'), $option('database-path'), $option('database-max-age'), (bool) $input->getOption('no-database'), $context->directory);
        } catch (\InvalidArgumentException $e) {
            $io->writeError('<error>' . ConsoleText::safe($e->getMessage()) . '</error>');

            return Plan::EXIT_ERROR;
        }
        if (!$settings->usesDatabase()) {
            // Nothing will locate a database, so the notes about how the settings were resolved have to
            // be carried here; the locator carries them itself on every other path. They also go to the
            // error stream, because a run that fails afterwards has no report to carry them in, and what
            // the project decided about the advisory source is worth knowing either way.
            array_push($this->planWarnings, ...$settings->notes);
            foreach ($settings->notes as $note) {
                $io->writeError('<comment>' . ConsoleText::safe($note) . '</comment>');
            }
            // A pinned digest says the operator will accept that database and nothing else. Letting the
            // project's composer.json turn the database off would hand it the gate.
            if ($option('database-sha256') !== null) {
                $io->writeError('<error>--database-sha256 was given, so the advisory database cannot be turned off' . ($settings->sourcesFromProject ? " by the analysed project's composer.json" : '') . '.</error>');

                return Plan::EXIT_ADVISORIES_UNAVAILABLE;
            }

            return self::composerAdvisoryProvider($composer, $context);
        }
        $rebuild = null;
        if ((bool) $input->getOption('rebuild-database')) {
            $downloader = $this->operator->httpDownloader();
            $tempDir = $locator->cacheDirectory() . '/tmp';
            $rebuild = static function (string $path) use ($downloader, $tempDir, $io): void {
                $io->writeError('<comment>Building the advisory database from the sources…</comment>');
                DatabaseBuildFactory::defaultBuilder($downloader, $tempDir)->build($path, static function (string $message) use ($io): void {
                    $io->writeError('<comment>' . ConsoleText::safe($message) . '</comment>', true, IOInterface::VERBOSE);
                }, ['engine_version' => Planner::engineVersion()]);
            };
        }
        if (!is_file($settings->path) && $settings->localSource() === null) {
            // The first run fetches several megabytes; later ones confirm the copy with one small
            // request. Without a word, a slow first run looks like a hang before planning even starts.
            $io->writeError(sprintf('<comment>Fetching the advisory database into %s; later runs check it with one small request.</comment>', ConsoleText::safe($settings->path)));
        }
        try {
            $located = $locator->locate($settings, $rebuild);
            if ($located !== null) {
                return new SqliteAdvisoryProvider(Database::open($located->path, $located->digest), $located->provenance);
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
            // A headline goes out as the run makes it, so a large lock file does not plan in silence for
            // minutes and read as a hang; the running commentary stays behind -v. Both go to the error
            // stream, so a report on standard output is still only the report.
            static function (string $message, bool $detail = true) use ($io): void {
                $io->writeError('<comment>' . ConsoleText::safe($message) . '</comment>', true, $detail ? IOInterface::VERBOSE : IOInterface::NORMAL);
            },
            $this->ignorePolicy($input, $io)->withIds($cliIgnores),
            is_string($minAge) && $minAge !== '' ? new ReleaseAgeGuard((int) $minAge) : null,
            max(1, (int) $input->getOption('solve-budget')),
            (bool) $input->getOption('accept-coverage-gaps'),
            self::parallelism($input, $io),
        );
    }

    /**
     * How many packages --parallelize asks to plan at once.
     *
     * A bad value is corrected rather than fatal: the number only decides how fast the run is, never
     * what it concludes, so refusing to start over it would cost the user their run for nothing.
     */
    private static function parallelism(InputInterface $input, IOInterface $io): int
    {
        $value = trim((string) $input->getOption('parallelize'));
        if (strtolower($value) === 'auto') {
            // Four is where the gain flattens on the lock files this was measured against, and it
            // keeps the memory a default can claim on a shared CI runner to something defensible.
            return max(1, min(4, self::processorCount()));
        }
        if (preg_match('{^[0-9]+$}', $value) !== 1 || (int) $value < 1) {
            $io->writeError(sprintf('<comment>--parallelize=%s is not a worker count; planning one package at a time. Give a positive whole number, or `auto`.</comment>', ConsoleText::safe($value)));

            return 1;
        }

        return (int) $value;
    }

    /** Processor cores available to this machine, or 1 when it will not say. */
    private static function processorCount(): int
    {
        if (function_exists('shell_exec') && !Platform::isWindows()) {
            $reported = @shell_exec('nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null');
            if (is_string($reported) && preg_match('{\d+}', $reported, $m) === 1) {
                return max(1, (int) $m[0]);
            }
        }

        return 1;
    }

    /**
     * The restrictions this run was started with, to be repeated on every command `--apply` runs.
     *
     * The standalone binary forces `--no-plugins --no-scripts` onto its own input so that no code from
     * the analysed project runs; the apply subprocess is a second Composer, and without these it would
     * run that project's scripts and plugins while the documentation says nothing of the project runs.
     * The rule is the same in plugin mode: an apply inherits whatever the caller restricted.
     *
     * @return list<string>
     */
    private static function safetyArguments(InputInterface $input): array
    {
        $arguments = [];
        foreach (['--no-plugins', '--no-scripts'] as $flag) {
            if ($input->hasParameterOption($flag, true)) {
                $arguments[] = $flag;
            }
        }

        return $arguments;
    }

    /**
     * Runs the recommended command in the project, then plans again so that what the report shows is
     * the state the run actually left behind rather than a prediction of it. Returns the new plan, or
     * an exit code when nothing ran or Composer failed. A project with no findings is left alone.
     *
     * @param list<string> $platformArguments
     */
    private function applyPlan(Plan $plan, ProjectContext $context, AdvisoryProvider $advisories, SolverInterface $solver, array $platformArguments, InputInterface $input, IOInterface $io): Plan|int
    {
        if ($plan->findings === []) {
            $io->writeError('<comment>Nothing to apply: no findings.</comment>');

            return $plan;
        }
        $applier = new Applier(SubprocessSolver::forRunningComposer()->composerCommand(), safetyArguments: self::safetyArguments($input));
        $refusal = $applier->refusal($plan, $context, (bool) $input->getOption('apply-root-constraints'), (bool) $input->getOption('apply-allow-dirty'));
        if ($refusal !== null) {
            $io->writeError('<error>--apply refused: ' . ConsoleText::safe($refusal) . '</error>');

            return Plan::EXIT_ERROR;
        }
        $combined = $plan->combined;
        \assert($combined !== null); // refusal() returns a reason when there is nothing verified to run
        try {
            $result = $applier->apply($combined->candidate, $context, $solver->supportsMinimalChanges(), (bool) $input->getOption('apply-no-install'), static function (string $line) use ($io): void {
                $io->writeError(ConsoleText::safe($line));
            });
        } catch (\RuntimeException $e) {
            $io->writeError('<error>--apply: ' . ConsoleText::safe($e->getMessage()) . '</error>');

            return Plan::EXIT_ERROR;
        }
        if ($result->outcome !== ApplyOutcome::Applied) {
            $io->writeError('<error>--apply failed: ' . ConsoleText::safe((string) $result->reason) . '</error>');

            return Plan::EXIT_ERROR;
        }

        // composer.json and composer.lock have moved; Composer's cached instance describes the state
        // from before the run, so the second plan is built on a fresh one.
        $this->resetComposer();
        $fresh = ProjectContext::fromComposer($this->requireComposer());
        $planner = $this->planner($input, $advisories, $solver, $platformArguments, $io);
        try {
            $after = $planner->plan($fresh, ScratchWorkspace::fromProject($fresh));
        } catch (AdvisoryLookupFailed $e) {
            $io->writeError('<error>Applied, but the state it left could not be checked: ' . ConsoleText::safe($e->getMessage()) . '</error>');

            return Plan::EXIT_ADVISORIES_UNAVAILABLE;
        }
        $after = $this->gate($after, $input, $io);
        if (is_int($after)) {
            return $after;
        }

        // The second plan is a fresh object: the disclosures the first run made about where advisories
        // came from, and who chose that, are not facts about the lock and would otherwise vanish exactly
        // when a reader is looking at an automated change.
        return $after->withWarnings([...$this->planWarnings, sprintf('Applied: %s. The composer.json and composer.lock from before the run are in %s. The findings below are what is left in the project now, not a prediction.', implode(' && ', $result->commands), (string) $result->backup)]);
    }

    /**
     * Which advisories to leave out. The analysed project's `config.audit.ignore` and
     * `config.policy.advisories` suppress findings, which is their purpose for a project you own; the
     * entries are attributed to the project in the report, and --no-project-ignores leaves them out for
     * a repository whose word you do not take.
     */
    private function ignorePolicy(InputInterface $input, IOInterface $io): IgnorePolicy
    {
        // Which rules are the project's is decided by reading both configurations and subtracting, not by
        // asking Composer who wrote a key: it records one source per top-level key, so a project that adds
        // to `config.audit.ignore` would make the operator's own entries in the same key look like its
        // own, and dropping "the project's" entries would drop centrally approved exceptions with them.
        // Rules carry their version constraint, so a project widening a scoped exception of the
        // operator's is a rule the operator did not write, and is reported as the project's.
        $operator = IgnorePolicy::fromComposerConfig($this->operator->config());
        $merged = IgnorePolicy::fromComposerConfig($this->requireComposer()->getConfig());
        $fromProject = array_values(array_diff($merged->rules(), $operator->rules()));

        if (!(bool) $input->getOption('no-project-ignores')) {
            return $merged->withProjectEntries($fromProject);
        }
        if ($fromProject !== []) {
            $this->planWarnings[] = sprintf('The analysed project\'s composer.json suppresses advisories (%s); --no-project-ignores left those entries out of this run. Exceptions from your own configuration still apply.', implode(', ', $fromProject));
            $io->writeError('<comment>' . ConsoleText::safe('--no-project-ignores: ignoring the project\'s own ignore entries (' . implode(', ', $fromProject) . ').') . '</comment>');
        }

        return $operator;
    }

    /** Applies --exposed, --accept-coverage-gaps, --fail-on and the baseline options to the plan; an exit code when they are malformed. */
    private function gate(Plan $plan, InputInterface $input, IOInterface $io): Plan|int
    {
        $exposed = array_values(array_filter(array_map('strval', (array) $input->getOption('exposed')), static fn (string $v): bool => trim($v) !== ''));
        if ($exposed !== []) {
            $plan = $plan->withExposure($exposed);
        }
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
        // Every destination is attempted, whatever the others do. Returning at the first one that
        // cannot be written left the rest holding whatever the last successful run put there, which is
        // the failure this is supposed to prevent: one unwritable path (a directory that does not
        // exist, a full disk) and a CI step goes on uploading a clean report for a run that failed.
        // A destination that cannot be written is reported and makes the run a tool error; it does not
        // decide anything for the destinations that can.
        $unwritable = [];
        foreach ($files as [$fileFormat, $path]) {
            if ($path === null || $fileFormat === ReportFormat::None) {
                continue;
            }
            if (@file_put_contents($path, $fileFormat->render($plan, $minimal, false, $lockLines)) === false) {
                $io->writeError(sprintf('<error>Could not write %s report to %s</error>', $fileFormat->value, $path));
                $unwritable[] = $path;
                continue;
            }
            $io->writeError(sprintf('%s report written to %s', ucfirst($fileFormat->value), $path));
        }
        if ($format !== ReportFormat::None) {
            $decorated = $format === ReportFormat::Text && $output->isDecorated();
            $output->write($format->render($plan, $minimal, $decorated, $lockLines), false, $decorated ? OutputInterface::OUTPUT_NORMAL : OutputInterface::OUTPUT_RAW);
        }

        return $unwritable !== [] ? Plan::EXIT_ERROR : $plan->exitCode();
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
