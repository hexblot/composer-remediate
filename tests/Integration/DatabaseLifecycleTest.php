<?php

declare(strict_types=1);

namespace Remediate\Tests\Integration;

use PHPUnit\Framework\TestCase;
use Remediate\Engine\Plan\Plan;
use Remediate\Tests\Support\CommandResult;
use Remediate\Tests\Support\CommandRunner;
use Remediate\Tests\Support\FixtureRunner;
use Remediate\Tests\Support\TlsPublisher;

/**
 * The advisory database's life through the real command, a real HTTPS publisher and the file on
 * disk, asserted together: exit code, report warnings, the provenance line in the header, and what
 * the path and the publisher's request log show. The layers (settings, locator, planner, renderers)
 * have their own tests; this one checks that they agree on a whole run.
 */
final class DatabaseLifecycleTest extends TestCase
{
    private const FIXTURE = FixtureRunner::FIXTURE_ROOT . '/synthetic-transitive-parent';

    private CommandRunner $runner;
    private string $project;
    private TlsPublisher $publisher;
    private string $path;

    protected function setUp(): void
    {
        $this->runner = new CommandRunner();
        $this->project = $this->runner->project(self::FIXTURE);
        $this->publisher = new TlsPublisher();
        $this->path = $this->project . '/.cache/advisories.sqlite';
        $certificate = $this->publisher->certificate();
        CommandRunner::editComposerJson($this->project, static function (array $json) use ($certificate): array {
            $json['config'] = ($json['config'] ?? []) + ['cafile' => $certificate];

            return $json;
        });
    }

    protected function tearDown(): void
    {
        $this->publisher->destroy();
        $this->runner->cleanup();
    }

    /** Builds a database from the fixture's private advisories, optionally with one FriendsOfPHP record too. */
    private function buildDatabase(string $output, bool $withFriendsOfPhp): void
    {
        $options = ['command' => 'remediate:db-build', '--output' => $output, '--include' => [self::FIXTURE . '/advisories.json'], '--enrich' => ['none']];
        if ($withFriendsOfPhp) {
            $checkout = $this->project . '/security-advisories';
            @mkdir($checkout . '/acme/helper', 0700, true);
            file_put_contents($checkout . '/acme/helper/CVE-2026-00002.yaml', "title: Helper\nlink: https://example.invalid/2\ncve: CVE-2026-00002\nbranches:\n    1.0.x:\n        time: 2026-02-01 09:00:00\n        versions: ['>=1.0.0', '<1.0.9']\nreference: composer://acme/helper\n");
            $options += ['--source' => ['friendsofphp'], '--friendsofphp-path' => $checkout];
        } else {
            $options += ['--source' => ['friendsofphp'], '--friendsofphp-path' => $this->project . '/empty-checkout'];
            @mkdir($this->project . '/empty-checkout', 0700, true);
        }
        $result = $this->runner->run($options, $this->project);
        self::assertSame(0, $result->exitCode, $result->describe());
    }

    /** @param array<string, mixed> $options */
    private function remediate(array $options = []): CommandResult
    {
        return $this->runner->run($options + ['command' => 'remediate', '--format' => 'json', '--database-path' => $this->path], $this->project);
    }

    /** @return array<string, mixed> */
    private static function report(CommandResult $result): array
    {
        $decoded = json_decode($result->stdout, true);
        self::assertIsArray($decoded, $result->describe());

        return $decoded;
    }

    public function testACopyIsDownloadedConfirmedReplacedAndKeptThroughAnOutage(): void
    {
        $this->buildDatabase($this->project . '/published-1.sqlite', true);
        $url = $this->publisher->publishDatabase($this->project . '/published-1.sqlite');

        // 1. Nothing at the path: download, verify, report the finding the database carries.
        $first = $this->remediate(['--database-location' => $url]);
        self::assertSame(Plan::EXIT_REMEDIATION_AVAILABLE, $first->exitCode, $first->describe());
        $report = self::report($first);
        self::assertStringContainsString('downloaded from ' . $url . ' (no local copy)', $report['analysis_metadata']['advisory_source']);
        self::assertSame([], $report['warnings']);
        self::assertFileExists($this->path);
        self::assertFileEquals($this->project . '/published-1.sqlite', $this->path);
        $status = json_decode((string) file_get_contents($this->path . '.status.json'), true);
        self::assertIsArray($status);
        self::assertTrue($status['verified']);
        self::assertSame($url, $status['url']);
        self::assertSame(['GET /latest.json', 'GET /advisories.sqlite'], $this->publisher->requests(), 'latest.json carries the digest; the sidecar is not needed');

        // 2. The copy matches what the publisher serves: one small request, nothing downloaded.
        $this->publisher->clearRequests();
        $second = $this->remediate(['--database-location' => $url]);
        self::assertSame(Plan::EXIT_REMEDIATION_AVAILABLE, $second->exitCode, $second->describe());
        self::assertStringContainsString('confirmed current against ' . $url . ' (same sha256 as the published database)', self::report($second)['analysis_metadata']['advisory_source']);
        self::assertSame(['GET /latest.json'], $this->publisher->requests());

        // 3. The publisher moves to a different dataset: the copy is stale and replaced.
        sleep(1); // a distinct built_at, so the two databases differ as files and as datasets
        $this->buildDatabase($this->project . '/published-2.sqlite', false);
        $this->publisher->publishDatabase($this->project . '/published-2.sqlite');
        $this->publisher->clearRequests();
        $third = $this->remediate(['--database-location' => $url]);
        self::assertSame(Plan::EXIT_REMEDIATION_AVAILABLE, $third->exitCode, $third->describe());
        self::assertStringContainsString('downloaded from ' . $url . ' (the copy built', self::report($third)['analysis_metadata']['advisory_source']);
        self::assertFileEquals($this->project . '/published-2.sqlite', $this->path);
        self::assertSame(['GET /latest.json', 'GET /advisories.sqlite'], $this->publisher->requests());

        // 4. The publisher is down: the copy is used and the report says so, with its age; the exit code is unchanged.
        $this->publisher->stop();
        $fourth = $this->remediate(['--database-location' => $url]);
        self::assertSame(Plan::EXIT_REMEDIATION_AVAILABLE, $fourth->exitCode, $fourth->describe());
        $report = self::report($fourth);
        self::assertStringContainsString('could not be confirmed current', $report['analysis_metadata']['advisory_source']);
        self::assertCount(1, $report['warnings']);
        self::assertStringContainsString('Could not confirm that the advisory database at ' . $this->path . ' is current', $report['warnings'][0]);
        self::assertStringContainsString('using the copy built 0 hours ago', $report['warnings'][0]);
        self::assertFileEquals($this->project . '/published-2.sqlite', $this->path, 'untouched');

        // 5. With a maximum age the same outage is a failure once the copy is too old (here: any age above zero hours is allowed, so it passes).
        $capped = $this->remediate(['--database-location' => $url, '--database-max-age' => '1']);
        self::assertSame(Plan::EXIT_REMEDIATION_AVAILABLE, $capped->exitCode, $capped->describe());

        // 6. Offline: no request is attempted (the server is down anyway) and the copy is used.
        $offline = $this->remediate(['--database-location' => $url, '--offline' => true]);
        self::assertSame(Plan::EXIT_REMEDIATION_AVAILABLE, $offline->exitCode, $offline->describe());
        self::assertStringContainsString('offline, using the copy built', self::report($offline)['analysis_metadata']['advisory_source']);
    }

    public function testAPrivateRebuildOverADownloadedCopySurvivesANewerPublication(): void
    {
        // 1. Download the public database into the path.
        $this->buildDatabase($this->project . '/public-1.sqlite', false);
        $url = $this->publisher->publishDatabase($this->project . '/public-1.sqlite');
        $first = $this->remediate(['--database-location' => $url]);
        self::assertSame(Plan::EXIT_REMEDIATION_AVAILABLE, $first->exitCode, $first->describe());
        self::assertFileExists($this->path . '.status.json');

        // 2. The operator rebuilds into the same path with a private advisory file (db-build --include).
        sleep(1);
        $this->buildDatabase($this->path, true);
        self::assertFileDoesNotExist($this->path . '.status.json', 'a build retires the download\'s status record');
        $privateBuild = (string) file_get_contents($this->path);

        // 3. The publisher moves on: the private build is kept, and the report says what that costs.
        sleep(1);
        $this->buildDatabase($this->project . '/public-2.sqlite', false);
        $this->publisher->publishDatabase($this->project . '/public-2.sqlite');
        $third = $this->remediate(['--database-location' => $url]);
        self::assertSame(Plan::EXIT_REMEDIATION_AVAILABLE, $third->exitCode, $third->describe());
        $report = self::report($third);
        self::assertStringEqualsFile($this->path, $privateBuild, 'the private build was not replaced');
        self::assertStringContainsString('a local build with private advisories, kept although', $report['analysis_metadata']['advisory_source']);
        self::assertCount(1, $report['warnings']);
        self::assertStringContainsString('private advisories (advisories.json)', $report['warnings'][0]);
        self::assertStringContainsString('remediate:db-build --if-stale and the same --include files', $report['warnings'][0]);
        self::assertNotContains('GET /advisories.sqlite', array_slice($this->publisher->requests(), -1));
    }

    public function testAPinnedDigestIsEnforcedOnTheDownloadAndOnEveryLaterUse(): void
    {
        $this->buildDatabase($this->project . '/published.sqlite', true);
        $url = $this->publisher->publishDatabase($this->project . '/published.sqlite');
        $digest = hash_file('sha256', $this->project . '/published.sqlite');

        $pinned = $this->remediate(['--database-location' => $url, '--database-sha256' => $digest]);
        self::assertSame(Plan::EXIT_REMEDIATION_AVAILABLE, $pinned->exitCode, $pinned->describe());

        $wrong = $this->remediate(['--database-location' => $url, '--database-sha256' => str_repeat('0', 64)]);
        self::assertSame(Plan::EXIT_ADVISORIES_UNAVAILABLE, $wrong->exitCode, $wrong->describe());
        self::assertStringContainsString('does not match the expected sha256', $wrong->stderr);
        self::assertStringNotContainsString('Asking the configured repositories', $wrong->stderr, 'a pin forbids the fallback');
        self::assertFileDoesNotExist($this->path, 'the copy that does not match the pin was discarded');
    }

    public function testAProjectChosenSourceNeverTouchesTheSharedFile(): void
    {
        $this->buildDatabase($this->project . '/published.sqlite', true);
        $shared = $this->publisher->publishDatabase($this->project . '/published.sqlite');
        $operator = $this->remediate(['--database-location' => $shared]);
        self::assertSame(Plan::EXIT_REMEDIATION_AVAILABLE, $operator->exitCode, $operator->describe());
        $sharedBytes = (string) file_get_contents($this->path);

        // The project points at its own publisher: a second server serving an empty database.
        $other = new TlsPublisher();
        try {
            $this->buildDatabase($this->project . '/empty.sqlite', false);
            // no --include this time: rebuild without the private file so the database is genuinely different
            $result = $this->runner->run(['command' => 'remediate:db-build', '--output' => $this->project . '/empty.sqlite', '--source' => ['friendsofphp'], '--friendsofphp-path' => $this->project . '/empty-checkout', '--enrich' => ['none']], $this->project);
            self::assertSame(0, $result->exitCode, $result->describe());
            $projectUrl = $other->publishDatabase($this->project . '/empty.sqlite');
            $otherCertificate = $other->certificate();
            // curl takes one cafile: bundle both certificates
            $bundle = $this->project . '/bundle.pem';
            file_put_contents($bundle, file_get_contents($this->publisher->certificate()) . file_get_contents($otherCertificate));
            CommandRunner::editComposerJson($this->project, static function (array $json) use ($projectUrl, $bundle): array {
                $json['config']['cafile'] = $bundle;
                $json['extra'] = ['remediate' => ['database' => $projectUrl]];

                return $json;
            });
            $previous = \Composer\Util\Platform::getEnv('REMEDIATE_DATABASE');
            \Composer\Util\Platform::clearEnv('REMEDIATE_DATABASE');
            try {
                $result = $this->runner->run(['command' => 'remediate', '--format' => 'json'], $this->project);
            } finally {
                is_string($previous) ? \Composer\Util\Platform::putEnv('REMEDIATE_DATABASE', $previous) : \Composer\Util\Platform::clearEnv('REMEDIATE_DATABASE');
            }
            self::assertSame(Plan::EXIT_CLEAN, $result->exitCode, $result->describe() . ' (the project-chosen database is empty, so the project looks clean)');
            $report = self::report($result);
            self::assertStringContainsString("Advisory source chosen by the analysed project's composer.json", implode("\n", $report['warnings']), 'a gate can see who chose the source');
            self::assertStringContainsString('/remediate/sources/', $report['analysis_metadata']['advisory_source'], 'its copy lives in a file of its own');
            self::assertStringEqualsFile($this->path, $sharedBytes, 'the operator\'s file is untouched');
        } finally {
            $other->destroy();
        }
    }
}
