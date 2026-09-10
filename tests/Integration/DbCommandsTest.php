<?php

declare(strict_types=1);

namespace Remediate\Tests\Integration;

use Composer\Util\Platform;
use PHPUnit\Framework\TestCase;
use Remediate\Engine\Advisory\Db\DatabaseLocator;
use Remediate\Engine\Plan\Plan;
use Remediate\Tests\Support\CommandRunner;
use Remediate\Tests\Support\FixtureRunner;

/**
 * remediate:db-build and remediate:db-status without the network: the FriendsOfPHP source reads a
 * local checkout and --include adds a Packagist-shaped file, so a database can be built, inspected
 * and then handed to `composer remediate` entirely from the fixture.
 */
final class DbCommandsTest extends TestCase
{
    private const FIXTURE = FixtureRunner::FIXTURE_ROOT . '/synthetic-transitive-parent';

    private CommandRunner $runner;
    private string $project;
    private string $checkout;

    protected function setUp(): void
    {
        $this->runner = new CommandRunner();
        $this->project = $this->runner->project(self::FIXTURE);
        // A two-file FriendsOfPHP/security-advisories checkout: one readable advisory, one broken file.
        $this->checkout = $this->project . '/security-advisories';
        mkdir($this->checkout . '/acme/helper', 0700, true);
        mkdir($this->checkout . '/acme/broken', 0700, true);
        file_put_contents($this->checkout . '/acme/helper/CVE-2026-00002.yaml', <<<'YAML'
title: Synthetic FriendsOfPHP advisory for acme/helper
link: https://example.invalid/advisories/CVE-2026-00002
cve: CVE-2026-00002
branches:
    1.0.x:
        time: 2026-02-01 09:00:00
        versions: ['>=1.0.0', '<1.0.9']
reference: composer://acme/helper
YAML);
        file_put_contents($this->checkout . '/acme/broken/BROKEN.yaml', "branches: [\nreference: composer://acme/broken\n");
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

    /** @param array<string, mixed> $options */
    private function build(array $options): \Remediate\Tests\Support\CommandResult
    {
        return $this->runner->run($options + ['command' => 'remediate:db-build', '--source' => ['friendsofphp'], '--friendsofphp-path' => $this->checkout, '--include' => [self::FIXTURE . '/advisories.json']], $this->project);
    }

    public function testBuildRejectsAnUnknownSource(): void
    {
        $result = $this->runner->run(['command' => 'remediate:db-build', '--source' => ['nvd', 'osv']], $this->project);
        self::assertSame(Plan::EXIT_ERROR, $result->exitCode, $result->describe());
        self::assertStringContainsString('Unknown source(s) nvd; choose from packagist, osv, friendsofphp', $result->stderr);
    }

    public function testBuildsFromLocalSourcesThenStatusAndRemediateReadTheResult(): void
    {
        $db = $this->project . '/advisories.sqlite';
        $result = $this->build(['--output' => $db]);
        self::assertSame(0, $result->exitCode, $result->describe());
        self::assertFileExists($db);
        self::assertStringContainsString('Advisory database written: ' . $db, $result->stdout);
        self::assertStringContainsString('2 advisories from 2 source records, 0 with conflicting ranges, 1 coverage gap,', $result->stdout);
        self::assertStringContainsString('Coverage gaps are upstream records the build could not interpret', $result->stdout);
        self::assertStringContainsString('composer remediate --database-location=' . $db, $result->stdout);
        self::assertStringContainsString('FriendsOfPHP: reading ' . $this->checkout, $result->stderr);
        self::assertStringContainsString('2 files, 1 records, 1 skipped (recorded as coverage gaps)', $result->stderr);

        $status = $this->runner->run(['command' => 'remediate:db-status', '--database-location' => $db], $this->project);
        self::assertSame(0, $status->exitCode, $status->describe());
        self::assertStringContainsString('Location: ' . $db, $status->stdout);
        self::assertStringContainsString('File: ' . $db, $status->stdout);
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
        self::assertSame('composer update acme/app-framework:1.1.0 -W -m', $report['findings'][0]['remediation']['command']);
    }

    public function testBuildWritesToTheDefaultPathWhichStatusAlsoUsesByDefault(): void
    {
        $result = $this->build([]);
        self::assertSame(0, $result->exitCode, $result->describe());
        self::assertFileExists($this->defaultBuildPath());

        $status = $this->runner->run(['command' => 'remediate:db-status'], $this->project);
        self::assertSame(0, $status->exitCode, $status->describe());
        self::assertStringContainsString('Location: ' . $this->defaultBuildPath(), $status->stdout);
        self::assertStringContainsString('advisory_count: 2', $status->stdout);
    }

    public function testStatusHonoursTheEnvironmentVariable(): void
    {
        $db = $this->project . '/env.sqlite';
        self::assertSame(0, $this->build(['--output' => $db])->exitCode);
        Platform::putEnv(DatabaseLocator::ENV, $db);
        try {
            $status = $this->runner->run(['command' => 'remediate:db-status'], $this->project);
        } finally {
            Platform::clearEnv(DatabaseLocator::ENV);
        }
        self::assertSame(0, $status->exitCode, $status->describe());
        self::assertStringContainsString('Location: ' . $db, $status->stdout);
    }

    public function testStatusOfAMissingDatabaseSaysHowToBuildOne(): void
    {
        $status = $this->runner->run(['command' => 'remediate:db-status', '--database-location' => $this->project . '/nowhere.sqlite'], $this->project);
        self::assertSame(Plan::EXIT_ADVISORIES_UNAVAILABLE, $status->exitCode, $status->describe());
        self::assertStringContainsString('does not exist', $status->stdout);
        self::assertStringContainsString('Build one with composer remediate:db-build', $status->stdout);
    }

    public function testStatusWarnsAboutADatabaseBuiltBeforeGapsWereRecorded(): void
    {
        $db = $this->project . '/old.sqlite';
        self::assertSame(0, $this->build(['--output' => $db])->exitCode);
        (new \PDO('sqlite:' . $db))->exec('DROP TABLE gap');

        $status = $this->runner->run(['command' => 'remediate:db-status', '--database-location' => $db], $this->project);
        self::assertSame(0, $status->exitCode, $status->describe());
        self::assertStringContainsString('Built before coverage gaps were recorded; rebuild', $status->stdout);
        self::assertStringNotContainsString('Coverage gaps (', $status->stdout);
    }
}
