<?php

declare(strict_types=1);

namespace Remediate\Tests\Integration;

use Composer\Util\Platform;
use PHPUnit\Framework\TestCase;
use Remediate\Engine\Advisory\Db\CoverageGap;
use Remediate\Engine\Advisory\Db\DatabaseBuilder;
use Remediate\Engine\Advisory\Db\DatabaseLocator;
use Remediate\Engine\Advisory\Db\Enrichment\EnrichmentSourceInterface;
use Remediate\Engine\Advisory\Db\Enrichment\ExploitRecord;
use Remediate\Engine\Advisory\Db\Source\JsonFileSource;
use Remediate\Engine\Plan\Plan;
use Remediate\Engine\Solver\InProcessSolver;
use Remediate\Tests\Support\CommandRunner;
use Remediate\Tests\Support\FixtureRunner;
use Remediate\Tests\Support\ScriptedSource;

/**
 * remediate:db-status and remediate:pr-body without the network, and `composer remediate` reading a
 * database built the way the release channel builds one: a public feed (scripted, under the name
 * FriendsOfPHP), a private advisory file, and exploit data.
 */
final class DbCommandsTest extends TestCase
{
    private const FIXTURE = FixtureRunner::FIXTURE_ROOT . '/synthetic-transitive-parent';
    /** A publisher nothing listens at: connection refused, no DNS, no waiting. */
    private const UNREACHABLE = 'https://127.0.0.1:9/advisories.sqlite';

    private CommandRunner $runner;
    private string $project;

    protected function setUp(): void
    {
        $this->runner = new CommandRunner();
        $this->project = $this->runner->project(self::FIXTURE);
    }

    protected function tearDown(): void
    {
        $this->runner->cleanup();
        @unlink($this->defaultBuildPath());
    }

    private function defaultBuildPath(): string
    {
        return Platform::getEnv('COMPOSER_CACHE_DIR') . '/remediate/advisories.sqlite';
    }

    /**
     * One readable FriendsOfPHP advisory, one file that could not be read (a coverage gap), and the
     * fixture's private advisory file.
     *
     * @param list<EnrichmentSourceInterface> $enrichments
     */
    private function build(string $output, array $enrichments = []): void
    {
        $feed = new ScriptedSource(
            'FriendsOfPHP',
            [ScriptedSource::advisory('FriendsOfPHP', 'CVE-2026-00002', 'acme/helper', '>=1.0.0,<1.0.9', 'CVE-2026-00002', 'Synthetic FriendsOfPHP advisory for acme/helper', '2026-02-01 09:00:00')],
            [new CoverageGap('FriendsOfPHP', 'acme/broken/BROKEN.yaml', 'acme/broken', 'YAML could not be parsed')],
        );
        @mkdir(dirname($output), 0700, true);
        (new DatabaseBuilder([$feed, new JsonFileSource(self::FIXTURE . '/advisories.json')], enrichments: $enrichments))->build($output, static function (): void {});
    }

    /**
     * @param array<string, ExploitRecord> $records
     * @param array<string, string>        $meta
     */
    private static function enrichment(string $name, array $records, array $meta): EnrichmentSourceInterface
    {
        return new class($name, $records, $meta) implements EnrichmentSourceInterface {
            /**
             * @param array<string, ExploitRecord> $records
             * @param array<string, string>        $meta
             */
            public function __construct(private readonly string $name, private readonly array $records, private readonly array $meta)
            {
            }

            public function name(): string
            {
                return $this->name;
            }

            public function fetch(callable $log): array
            {
                return ['records' => $this->records, 'meta' => $this->meta];
            }
        };
    }

    public function testExploitDataInTheDatabaseReachesStatusAndTheReport(): void
    {
        $db = $this->project . '/enriched.sqlite';
        $this->build($db, [
            self::enrichment('EPSS', ['CVE-2026-00001' => new ExploitRecord('CVE-2026-00001', 0.93412, 0.99871), 'CVE-2026-00002' => new ExploitRecord('CVE-2026-00002', 0.5, 0.5)], ['epss_score_date' => '2026-09-09T00:00:00+0000']),
            self::enrichment('KEV', ['CVE-2026-00001' => new ExploitRecord('CVE-2026-00001', null, null, new \DateTimeImmutable('2026-02-01'), true)], ['kev_date_released' => '2026-09-09T14:00:00Z']),
        ]);

        $status = $this->runner->run(['command' => 'remediate:db-status', '--database-location' => $db], $this->project);
        self::assertSame(0, $status->exitCode, $status->describe());
        self::assertStringContainsString('Exploit data: 2 CVEs, EPSS scored 2026-09-09T00:00:00+0000, KEV catalogue 2026-09-09T14:00:00Z (1 listed here)', $status->stdout);
        self::assertStringNotContainsString('Built before exploit data', $status->stdout);

        $remediate = $this->runner->run(['command' => 'remediate', '--database-location' => $db, '--format' => 'json'], $this->project);
        self::assertSame(Plan::EXIT_REMEDIATION_AVAILABLE, $remediate->exitCode, $remediate->describe());
        $report = $remediate->json();
        $advisory = $report['findings'][0]['advisories'][0];
        self::assertSame('CVE-2026-00001', $advisory['cve']);
        self::assertSame(0.93412, $advisory['epss']);
        self::assertSame('2026-02-01', $advisory['kev_added']);
        self::assertSame(1, $report['summary']['packages_known_exploited']);
        self::assertStringContainsString('EPSS scored 2026-09-09, KEV catalogue 2026-09-09', $report['analysis_metadata']['advisory_source']);
    }

    public function testADatabaseBuiltWithoutEnrichmentSaysSoInStatus(): void
    {
        $db = $this->project . '/plain.sqlite';
        $this->build($db);
        (new \PDO('sqlite:' . $db))->exec('DROP TABLE exploit');
        $status = $this->runner->run(['command' => 'remediate:db-status', '--database-location' => $db], $this->project);
        self::assertSame(0, $status->exitCode, $status->describe());
        self::assertStringContainsString('Built before exploit data (EPSS, CISA KEV) was recorded', $status->stdout);
    }

    public function testStatusAndRemediateReadABuildFromAFeedAndAPrivateFile(): void
    {
        $db = $this->project . '/advisories.sqlite';
        $this->build($db);

        $status = $this->runner->run(['command' => 'remediate:db-status', '--database-location' => $db], $this->project);
        self::assertSame(0, $status->exitCode, $status->describe());
        self::assertStringContainsString('Path: ' . $db, $status->stdout);
        // "File" is the resolved path, which is not always the one that was asked for: on macOS the
        // temporary directory is reached through a symbolic link (/var -> /private/var), and on
        // Windows realpath answers in backslashes. Reporting where the file really is, is the point
        // of the line, so the assertion resolves it too rather than the report leaving it alone.
        self::assertStringContainsString('File: ' . (realpath($db) ?: $db), $status->stdout);
        self::assertStringContainsString('source: FriendsOfPHP, 1 records, fetched ', $status->stdout);
        self::assertStringContainsString('source: local:advisories.json, 1 records', $status->stdout);
        self::assertStringContainsString('Coverage gaps (1, showing up to 50)', $status->stdout);
        self::assertStringContainsString('acme/broken/BROKEN.yaml', $status->stdout);
        self::assertStringNotContainsString('Built before coverage gaps were recorded', $status->stdout);

        $remediate = $this->runner->run(['command' => 'remediate', '--database-location' => $db, '--format' => 'json'], $this->project);
        self::assertSame(Plan::EXIT_REMEDIATION_AVAILABLE, $remediate->exitCode, $remediate->describe());
        $report = $remediate->json();
        self::assertCount(1, $report['findings'], 'acme/helper 1.0.x is not in the lock at a vulnerable version, acme/vuln-lib is');
        self::assertSame('acme/vuln-lib', $report['findings'][0]['package']);
        self::assertSame('composer update acme/app-framework:1.1.0 -W' . ((new InProcessSolver())->supportsMinimalChanges() ? ' -m' : ''), $report['findings'][0]['remediation']['command']);
    }

    public function testStatusReadsTheDefaultPathByDefault(): void
    {
        $this->build($this->defaultBuildPath());

        // With the publisher unreachable, status reports on the copy at the default path as it is.
        $status = $this->runner->run(['command' => 'remediate:db-status', '--database-location' => self::UNREACHABLE], $this->project);
        self::assertSame(0, $status->exitCode, $status->describe());
        self::assertStringContainsString('Path: ' . $this->defaultBuildPath() . ' (default)', $status->stdout);
        self::assertStringContainsString('Source: ' . self::UNREACHABLE, $status->stdout);
        self::assertStringContainsString('Status: could not be confirmed current', $status->stdout);
        self::assertStringContainsString('advisory_count: 2', $status->stdout);
    }

    public function testStatusOfTheDefaultConfigurationSaysWhichSettingsAreDefaults(): void
    {
        // The test bootstrap points REMEDIATE_DATABASE at the configured repositories.
        $status = $this->runner->run(['command' => 'remediate:db-status'], $this->project);
        self::assertSame(0, $status->exitCode, $status->describe());
        self::assertStringContainsString('No advisory database is configured (source set to composer)', $status->stdout);

        $status = $this->runner->run(['command' => 'remediate:db-status', '--database-location' => self::UNREACHABLE], $this->project);
        self::assertSame(Plan::EXIT_ADVISORIES_UNAVAILABLE, $status->exitCode, $status->describe());
        self::assertStringContainsString('No advisory database at ' . $this->defaultBuildPath() . ' and none could be fetched', $status->stdout);
        self::assertStringContainsString('falls back to the configured repositories meanwhile', $status->stdout);
    }

    public function testStatusReadsAnExplicitDatabasePath(): void
    {
        $db = $this->project . '/team.sqlite';
        $this->build($db);

        $status = $this->runner->run(['command' => 'remediate:db-status', '--database-path' => $db, '--database-location' => self::UNREACHABLE, '--offline' => true], $this->project);
        self::assertSame(0, $status->exitCode, $status->describe());
        self::assertStringContainsString('Path: ' . $db, $status->stdout);
        self::assertStringContainsString('Status: offline, using the copy built', $status->stdout);
    }

    public function testAMalformedMaximumAgeIsAnOptionError(): void
    {
        $status = $this->runner->run(['command' => 'remediate:db-status', '--database-location' => self::UNREACHABLE, '--database-max-age' => 'soon'], $this->project);
        self::assertSame(Plan::EXIT_ERROR, $status->exitCode, $status->describe());
        self::assertStringContainsString('--database-max-age must be a number of hours', $status->stderr);
    }

    public function testStatusHonoursTheEnvironmentVariable(): void
    {
        $db = $this->project . '/env.sqlite';
        $this->build($db);
        $previous = Platform::getEnv(DatabaseLocator::ENV);
        Platform::putEnv(DatabaseLocator::ENV, $db);
        try {
            $status = $this->runner->run(['command' => 'remediate:db-status'], $this->project);
        } finally {
            is_string($previous) ? Platform::putEnv(DatabaseLocator::ENV, $previous) : Platform::clearEnv(DatabaseLocator::ENV);
        }
        self::assertSame(0, $status->exitCode, $status->describe());
        self::assertStringContainsString('Path: ' . $db, $status->stdout);
        self::assertStringContainsString('Status: a local file named by --database-location', $status->stdout);
    }

    public function testStatusOfAMissingDatabaseSaysWhereOneComesFrom(): void
    {
        $status = $this->runner->run(['command' => 'remediate:db-status', '--database-location' => $this->project . '/nowhere.sqlite'], $this->project);
        self::assertSame(Plan::EXIT_ADVISORIES_UNAVAILABLE, $status->exitCode, $status->describe());
        self::assertStringContainsString('does not exist', $status->stdout);
        self::assertStringContainsString('build one with the release channel', $status->stdout);
    }

    public function testStatusWarnsAboutADatabaseBuiltBeforeGapsWereRecorded(): void
    {
        $db = $this->project . '/old.sqlite';
        $this->build($db);
        (new \PDO('sqlite:' . $db))->exec('DROP TABLE gap');

        $status = $this->runner->run(['command' => 'remediate:db-status', '--database-location' => $db], $this->project);
        self::assertSame(0, $status->exitCode, $status->describe());
        self::assertStringContainsString('Built before coverage gaps were recorded; rebuild', $status->stdout);
        self::assertStringNotContainsString('Coverage gaps (', $status->stdout);
    }

    public function testThePullRequestBodyCommandRendersTwoReports(): void
    {
        $before = $this->project . '/before.json';
        $after = $this->project . '/after.json';
        file_put_contents($before, json_encode([
            'exit_code' => 1,
            'warnings' => [],
            'summary' => ['packages' => 1, 'advisories' => 1],
            'findings' => [['package' => 'acme/lib', 'version' => '1.0.0', 'advisories' => [['id' => 'PKSA-1', 'cve' => 'CVE-2026-1', 'severity' => 'high', 'link' => null]], 'remediation' => ['status' => 'verified', 'command' => 'composer update acme/lib']]],
        ], JSON_THROW_ON_ERROR));
        file_put_contents($after, json_encode(['exit_code' => 0, 'warnings' => ['Applied: composer update acme/lib. The composer.json and composer.lock from before the run are in /tmp/x.'], 'summary' => ['packages' => 0, 'advisories' => 0], 'findings' => []], JSON_THROW_ON_ERROR));
        file_put_contents($this->project . '/commands.txt', "composer update acme/lib\n");

        $result = $this->runner->run(['command' => 'remediate:pr-body', 'before' => $before, 'after' => $after, '--commands' => $this->project . '/commands.txt'], $this->project);

        self::assertSame(0, $result->exitCode, $result->describe());
        self::assertStringContainsString('1 of 1 advisories closed, on 1 of 1 packages.', $result->stdout);
        self::assertStringContainsString('composer update acme/lib', $result->stdout);
        self::assertStringContainsString('CVE-2026-1', $result->stdout);
        self::assertStringNotContainsString('## Still open', $result->stdout);
    }

    public function testThePullRequestBodyCommandRejectsAReportItCannotRead(): void
    {
        $result = $this->runner->run(['command' => 'remediate:pr-body', 'before' => $this->project . '/missing.json', 'after' => $this->project . '/missing.json'], $this->project);

        self::assertSame(Plan::EXIT_ERROR, $result->exitCode, $result->describe());
        self::assertStringContainsString('is not a readable JSON report', $result->stderr);
    }
}
