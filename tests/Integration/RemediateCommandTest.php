<?php

declare(strict_types=1);

namespace Remediate\Tests\Integration;

use Composer\Util\Platform;
use PHPUnit\Framework\TestCase;
use Remediate\Engine\Advisory\Db\DatabaseLocator;
use Remediate\Engine\Plan\Plan;
use Remediate\Engine\Solver\InProcessSolver;
use Remediate\Tests\Support\CommandResult;
use Remediate\Tests\Support\CommandRunner;
use Remediate\Tests\Support\FixtureRunner;

/**
 * `composer remediate` end to end through Composer's console application: option validation, the
 * exit-code contract, report files, --fail-on, the baseline workflow and the advisory-source
 * selection, all against the synthetic fixture (one high-severity finding, remediation verified).
 */
final class RemediateCommandTest extends TestCase
{
    private const FIXTURE = FixtureRunner::FIXTURE_ROOT . '/synthetic-transitive-parent';
    private const ADVISORIES = self::FIXTURE . '/advisories.json';
    private const CVE = 'CVE-2026-00001';

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
    }

    /**
     * The verified command for the fixture's finding. Composer releases without --minimal-changes
     * (before 2.9, as in the CI matrix's 2.4 job) recommend the same command without -m.
     */
    private static function remediation(): string
    {
        return 'composer update acme/app-framework:1.1.0 -W' . ((new InProcessSolver())->supportsMinimalChanges() ? ' -m' : '');
    }

    /** @param array<string, mixed> $options */
    private function remediate(array $options = []): CommandResult
    {
        return $this->runner->run($options + ['command' => 'remediate', '--advisories-file' => self::ADVISORIES], $this->project);
    }

    public function testRejectsAnUnknownFormatBeforeTouchingTheProject(): void
    {
        $result = $this->remediate(['--format' => 'yaml']);
        self::assertSame(Plan::EXIT_ERROR, $result->exitCode, $result->describe());
        self::assertStringContainsString('Unknown format "yaml"', $result->stderr);
        self::assertSame('', $result->stdout);
    }

    public function testRejectsAReportPathWhoseFormatCannotBeInferred(): void
    {
        $result = $this->remediate(['--output' => ['report.pdf']]);
        self::assertSame(Plan::EXIT_ERROR, $result->exitCode, $result->describe());
        self::assertStringContainsString('Cannot infer a report format from "report.pdf"', $result->stderr);
    }

    public function testRejectsAnUnknownSolver(): void
    {
        $result = $this->remediate(['--solver' => 'oracle']);
        self::assertSame(Plan::EXIT_ERROR, $result->exitCode, $result->describe());
        self::assertStringContainsString('Unknown solver "oracle"', $result->stderr);
    }

    public function testRejectsANonNumericReleaseAge(): void
    {
        $result = $this->remediate(['--min-release-age' => 'soon']);
        self::assertSame(Plan::EXIT_ERROR, $result->exitCode, $result->describe());
        self::assertStringContainsString('--min-release-age must be a whole number of days, got "soon"', $result->stderr);
    }

    public function testNeedsALockFile(): void
    {
        unlink($this->project . '/composer.lock');
        $result = $this->remediate();
        self::assertSame(Plan::EXIT_ERROR, $result->exitCode, $result->describe());
        self::assertStringContainsString('No composer.lock found', $result->stderr);
    }

    public function testReportsTheVerifiedRemediationAsText(): void
    {
        $result = $this->remediate();
        self::assertSame(Plan::EXIT_REMEDIATION_AVAILABLE, $result->exitCode, $result->describe());
        self::assertStringContainsString(self::CVE, $result->stdout);
        self::assertStringContainsString(self::remediation(), $result->stdout);
        self::assertStringContainsString('acme/vuln-lib', $result->stdout);
    }

    public function testEverySolverChoiceReachesTheSameRemediation(): void
    {
        foreach (['in-process', 'auto'] as $solver) {
            $result = $this->remediate(['--solver' => $solver, '--format' => 'json']);
            self::assertSame(Plan::EXIT_REMEDIATION_AVAILABLE, $result->exitCode, $solver . ': ' . $result->describe());
            self::assertSame(self::remediation(), $result->json()['findings'][0]['remediation']['command'], $solver);
        }
    }

    public function testWritesEveryRequestedReportFileNextToTheJsonOnStdout(): void
    {
        $html = $this->project . '/report.html';
        $sarif = $this->project . '/scan';
        $gitlab = $this->project . '/gl-dependency-scanning-report.json';
        $cyclonedx = $this->project . '/sbom.cdx.json';
        $text = $this->project . '/report.txt';
        $result = $this->remediate(['--format' => 'json', '--output' => [$html, 'sarif:' . $sarif, $gitlab, $cyclonedx, $text]]);
        self::assertSame(Plan::EXIT_REMEDIATION_AVAILABLE, $result->exitCode, $result->describe());

        $report = $result->json();
        self::assertSame(Plan::EXIT_REMEDIATION_AVAILABLE, $report['exit_code']);
        self::assertSame('acme/vuln-lib', $report['findings'][0]['package']);
        self::assertSame('verified', $report['findings'][0]['remediation']['status']);
        self::assertSame(self::remediation(), $report['findings'][0]['remediation']['command']);

        self::assertStringStartsWith('<!DOCTYPE html>', (string) file_get_contents($html));
        self::assertSame('2.1.0', json_decode((string) file_get_contents($sarif), true)['version'] ?? null);
        self::assertSame('dependency_scanning', json_decode((string) file_get_contents($gitlab), true)['scan']['type'] ?? null);
        self::assertSame('CycloneDX', json_decode((string) file_get_contents($cyclonedx), true)['bomFormat'] ?? null);
        self::assertStringContainsString(self::remediation(), (string) file_get_contents($text));
        foreach (['Html', 'Sarif', 'Gitlab', 'Cyclonedx', 'Text'] as $label) {
            self::assertStringContainsString($label . ' report written to', $result->stderr);
        }
    }

    public function testFormatNoneLeavesStdoutEmpty(): void
    {
        $json = $this->project . '/report.json';
        $result = $this->remediate(['--format' => 'none', '--output' => [$json]]);
        self::assertSame(Plan::EXIT_REMEDIATION_AVAILABLE, $result->exitCode, $result->describe());
        self::assertSame('', $result->stdout);
        self::assertFileExists($json);
    }

    public function testAnUnwritableReportPathIsAnError(): void
    {
        $result = $this->remediate(['--output' => [$this->project . '/no/such/dir/report.json']]);
        self::assertSame(Plan::EXIT_ERROR, $result->exitCode, $result->describe());
        self::assertStringContainsString('Could not write json report', $result->stderr);
    }

    public function testFailOnThresholdDecidesTheExitCodeButNotTheReport(): void
    {
        $result = $this->remediate(['--fail-on' => 'critical']);
        self::assertSame(Plan::EXIT_CLEAN, $result->exitCode, $result->describe());
        self::assertStringContainsString(self::remediation(), $result->stdout, 'the high-severity finding is still reported');

        $result = $this->remediate(['--fail-on' => 'high']);
        self::assertSame(Plan::EXIT_REMEDIATION_AVAILABLE, $result->exitCode, $result->describe());

        $result = $this->remediate(['--fail-on' => 'severe']);
        self::assertSame(Plan::EXIT_ERROR, $result->exitCode, $result->describe());
        self::assertStringContainsString('Unknown severity "severe"', $result->stderr);
    }

    public function testIgnoredAdvisoriesDoNotCount(): void
    {
        $result = $this->remediate(['--ignore' => [self::CVE], '--format' => 'json']);
        self::assertSame(Plan::EXIT_CLEAN, $result->exitCode, $result->describe());
        self::assertSame(Plan::EXIT_CLEAN, $result->json()['exit_code']);
    }

    public function testASearchBudgetTooSmallToReachTheFixIsReportedAsUnremediated(): void
    {
        // One solver run only: the first candidate updates acme/vuln-lib alone, which lands on 1.0.4 and is still vulnerable.
        $result = $this->remediate(['--solve-budget' => '1', '--max-candidates' => '1', '--format' => 'json']);
        self::assertSame(Plan::EXIT_NO_REMEDIATION, $result->exitCode, $result->describe());
        $finding = $result->json()['findings'][0];
        self::assertNotSame('verified', $finding['remediation']['status'] ?? null);
        self::assertSame(1, $finding['solver_runs']);
    }

    public function testBaselineWorkflow(): void
    {
        $baseline = $this->project . '/remediate-baseline.json';

        $result = $this->remediate(['--update-baseline' => true]);
        self::assertSame(Plan::EXIT_ERROR, $result->exitCode, $result->describe());
        self::assertStringContainsString('--update-baseline needs --baseline=<file>', $result->stderr);

        $result = $this->remediate(['--baseline' => $baseline]);
        self::assertSame(Plan::EXIT_REMEDIATION_AVAILABLE, $result->exitCode, $result->describe());
        self::assertStringContainsString('does not exist; run with --update-baseline to create it', $result->stderr);

        $result = $this->remediate(['--baseline' => $baseline, '--update-baseline' => true]);
        self::assertSame(Plan::EXIT_CLEAN, $result->exitCode, 'the accepted state is applied in the same run: ' . $result->describe());
        self::assertStringContainsString('Baseline written to ' . $baseline . ' (1 finding accepted)', $result->stderr);
        $written = json_decode((string) file_get_contents($baseline), true);
        self::assertSame('acme/vuln-lib', $written['findings'][0]['package'] ?? null);

        $result = $this->remediate(['--baseline' => $baseline, '--format' => 'json']);
        self::assertSame(Plan::EXIT_CLEAN, $result->exitCode, $result->describe());
        $finding = $result->json()['findings'][0];
        self::assertTrue($finding['baselined']);
        self::assertFalse($finding['counts_for_exit']);
        self::assertSame(self::remediation(), $finding['remediation']['command'], 'a baselined finding keeps its remediation');

        file_put_contents($baseline, '{"not":"a baseline"}');
        $result = $this->remediate(['--baseline' => $baseline]);
        self::assertSame(Plan::EXIT_ERROR, $result->exitCode, $result->describe());
        self::assertStringContainsString('is not a baseline file', $result->stderr);
    }

    public function testAnUnreadableAdvisoriesFileMeansAdvisoriesUnavailable(): void
    {
        $result = $this->remediate(['--advisories-file' => $this->project . '/missing.json']);
        self::assertSame(Plan::EXIT_ADVISORIES_UNAVAILABLE, $result->exitCode, $result->describe());
        self::assertStringContainsString('Advisory data unavailable: Cannot read advisory file', $result->stderr);
        self::assertStringNotContainsString('Offline mode', $result->stderr);

        $result = $this->remediate(['--advisories-file' => $this->project . '/missing.json', '--offline' => true]);
        self::assertSame(Plan::EXIT_ADVISORIES_UNAVAILABLE, $result->exitCode, $result->describe());
        self::assertStringContainsString('Offline mode: the advisory database must already be at its path', $result->stderr);
        self::assertFalse(Platform::getEnv('COMPOSER_DISABLE_NETWORK'), 'the runner undoes what --offline exports');
    }

    public function testOfflineRunAgainstALocalSnapshotSucceeds(): void
    {
        $result = $this->remediate(['--offline' => true, '--format' => 'json']);
        self::assertSame(Plan::EXIT_REMEDIATION_AVAILABLE, $result->exitCode, $result->describe());
        self::assertSame(self::remediation(), $result->json()['findings'][0]['remediation']['command']);
    }

    public function testAMissingDatabaseMeansAdvisoriesUnavailableWhereverItIsConfigured(): void
    {
        $missing = $this->project . '/advisories.sqlite';
        $base = ['command' => 'remediate'];

        $result = $this->runner->run($base + ['--database-location' => $missing], $this->project);
        self::assertSame(Plan::EXIT_ADVISORIES_UNAVAILABLE, $result->exitCode, $result->describe());
        self::assertStringContainsString('Advisory database unavailable: Advisory database ' . $missing . ' does not exist.', $result->stderr);

        $previous = Platform::getEnv(DatabaseLocator::ENV);
        Platform::putEnv(DatabaseLocator::ENV, $missing);
        try {
            $result = $this->runner->run($base, $this->project);
        } finally {
            is_string($previous) ? Platform::putEnv(DatabaseLocator::ENV, $previous) : Platform::clearEnv(DatabaseLocator::ENV);
        }
        self::assertSame(Plan::EXIT_ADVISORIES_UNAVAILABLE, $result->exitCode, 'via ' . DatabaseLocator::ENV . ': ' . $result->describe());

        CommandRunner::editComposerJson($this->project, static function (array $json) use ($missing): array {
            $json['extra'] = ['remediate' => ['database' => $missing]];

            return $json;
        });
        $result = $this->runner->run($base, $this->project);
        self::assertSame(Plan::EXIT_ADVISORIES_UNAVAILABLE, $result->exitCode, 'via extra.remediate.database: ' . $result->describe());
    }

    public function testAnUnreachableDatabaseSourceFallsBackToTheConfiguredRepositoriesWithAWarning(): void
    {
        $result = $this->runner->run(['command' => 'remediate', '--database-location' => 'https://127.0.0.1:9/advisories.sqlite'], $this->project);
        self::assertSame(Plan::EXIT_ADVISORIES_UNAVAILABLE, $result->exitCode, $result->describe());
        self::assertStringContainsString('No advisory database at', $result->stderr);
        self::assertStringContainsString('Asking the configured repositories instead.', $result->stderr);
        self::assertStringContainsString('None of the configured repositories provides security advisories', $result->stderr, 'the fallback ran and failed for its own reason');
    }

    public function testAPinnedDigestForbidsTheFallback(): void
    {
        $result = $this->runner->run(['command' => 'remediate', '--database-location' => 'https://127.0.0.1:9/advisories.sqlite', '--database-sha256' => str_repeat('a', 64)], $this->project);
        self::assertSame(Plan::EXIT_ADVISORIES_UNAVAILABLE, $result->exitCode, $result->describe());
        self::assertStringContainsString('--database-sha256 was given, so no other source is acceptable', $result->stderr);
        self::assertStringNotContainsString('Asking the configured repositories', $result->stderr);
    }

    public function testNoDatabaseAsksTheConfiguredRepositoriesDirectly(): void
    {
        $result = $this->runner->run(['command' => 'remediate', '--no-database' => true, '--database-location' => 'https://127.0.0.1:9/advisories.sqlite'], $this->project);
        self::assertSame(Plan::EXIT_ADVISORIES_UNAVAILABLE, $result->exitCode, $result->describe());
        self::assertStringNotContainsString('advisory database', strtolower($result->stderr));
        self::assertStringContainsString('None of the configured repositories provides security advisories', $result->stderr);
    }

    public function testAMalformedMaximumAgeIsAnOptionError(): void
    {
        $result = $this->runner->run(['command' => 'remediate', '--database-location' => 'https://127.0.0.1:9/advisories.sqlite', '--database-max-age' => 'soon'], $this->project);
        self::assertSame(Plan::EXIT_ERROR, $result->exitCode, $result->describe());
        self::assertStringContainsString('--database-max-age must be a number of hours', $result->stderr);
    }

    public function testWithoutAnAdvisorySourceTheConfiguredRepositoriesAreAskedAndAnAbsenceIsAnError(): void
    {
        // The fixture disables packagist.org and its static repository carries no advisories: the
        // in-process adapter reports that nothing can answer, and this is not retried through
        // `composer audit`, which would face the same repositories.
        $result = $this->runner->run(['command' => 'remediate'], $this->project);
        self::assertSame(Plan::EXIT_ADVISORIES_UNAVAILABLE, $result->exitCode, $result->describe());
        self::assertStringContainsString('None of the configured repositories provides security advisories', $result->stderr);
        self::assertStringNotContainsString('composer audit', $result->stderr);
    }

    public function testPlatformFlagsAreRepeatedInTheRecommendedCommand(): void
    {
        $result = $this->remediate(['--ignore-platform-reqs' => true, '--format' => 'json']);
        self::assertSame(Plan::EXIT_REMEDIATION_AVAILABLE, $result->exitCode, $result->describe());
        self::assertStringContainsString('--ignore-platform-reqs', $result->json()['findings'][0]['remediation']['command']);

        $result = $this->remediate(['--ignore-platform-req' => ['ext-sodium', 'php'], '--format' => 'json']);
        self::assertSame(Plan::EXIT_REMEDIATION_AVAILABLE, $result->exitCode, $result->describe());
        $command = $result->json()['findings'][0]['remediation']['command'];
        self::assertStringContainsString('--ignore-platform-req=ext-sodium', $command);
        self::assertStringContainsString('--ignore-platform-req=php', $command);
    }
}
