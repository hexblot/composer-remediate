<?php

declare(strict_types=1);

namespace Remediate\Tests\Contract;

use Composer\Util\Platform;
use PHPUnit\Framework\TestCase;
use Remediate\Engine\Advisory\AdvisoryLookupFailed;
use Remediate\Engine\Advisory\Db\AffectedRange;
use Remediate\Engine\Advisory\Db\Database;
use Remediate\Engine\Advisory\Db\DatabaseWriter;
use Remediate\Engine\Advisory\Db\NormalizedAdvisory;
use Remediate\Engine\Advisory\Db\SqliteAdvisoryProvider;
use Remediate\Tests\Support\CommandRunner;
use Remediate\Tests\Support\ScriptedProject;
use Remediate\Tests\Support\TlsPublisher;

/**
 * Invariant: once a particular database has been vouched for, every later command reads those bytes
 * or refuses to run.
 *
 * Verifying a file and then naming it by its path is not the same thing as using it. The path stays
 * refreshable: between the check and the scan, the publisher can move on and the tool will happily
 * replace what was checked with something newer, so the run ends up reading bytes nobody vouched for
 * and reporting a clean lock on them. A digest is what binds the two together, and the point of this
 * test is that the binding holds across every command in a run, not just the first.
 */
final class VerifiedDatabaseContractTest extends TestCase
{
    public function testAPinnedDigestIsEnforcedOnEveryCommandAndSurvivesAPublicationChange(): void
    {
        $project = new ScriptedProject(['acme/lib' => '^1'], [['acme/lib', '1.0.0']]);
        $publisher = new TlsPublisher();
        $previous = Platform::getEnv('COMPOSER_CAFILE');
        try {
            Platform::putEnv('COMPOSER_CAFILE', $publisher->certificate());

            $first = $project->directory . '/first.sqlite';
            (new DatabaseWriter())->write([], [], $first);
            $url = $publisher->publishDatabase($first);
            $cache = $project->directory . '/cache.sqlite';
            $runner = new CommandRunner();

            // What an operator verifies: one specific file, and its digest.
            $status = $runner->run(['command' => 'remediate:db-status', '--database-location' => $url, '--database-path' => $cache], $project->directory);
            self::assertSame(0, $status->exitCode, $status->describe());
            $digest = hash_file('sha256', $cache);
            self::assertIsString($digest);

            // The publisher then moves on, which is exactly what it is supposed to do.
            $second = $project->directory . '/second.sqlite';
            (new DatabaseWriter())->write([self::advisory()], [], $second);
            $publisher->publishDatabase($second);
            self::assertNotSame($digest, hash_file('sha256', $second), 'the publication has to have actually changed for this to test anything');

            // Every command that names the digest now refuses the new bytes rather than reading them.
            /** @var array<string, array<string, mixed>> $commands */
            $commands = [
                'a scan' => ['command' => 'remediate', '--format' => 'json'],
                'a scan that would apply' => ['command' => 'remediate', '--format' => 'json', '--apply' => true],
                'a status check' => ['command' => 'remediate:db-status'],
            ];
            foreach ($commands as $what => $arguments) {
                $run = $runner->run($arguments + ['--database-location' => $url, '--database-path' => $cache, '--database-sha256' => $digest], $project->directory);
                self::assertSame(4, $run->exitCode, $what . ' read bytes that were never verified' . "\n" . $run->describe());
            }

            // And without the digest, the same commands take the new publication silently, which is
            // the behaviour the pin exists to prevent and the reason a path alone is not enough.
            $unpinned = $runner->run(['command' => 'remediate', '--format' => 'json', '--database-location' => $url, '--database-path' => $cache], $project->directory);
            self::assertNotSame(4, $unpinned->exitCode, $unpinned->describe());
            self::assertNotSame($digest, hash_file('sha256', $cache), 'the unpinned run was expected to move to the new publication');
        } finally {
            is_string($previous) ? Platform::putEnv('COMPOSER_CAFILE', $previous) : Platform::clearEnv('COMPOSER_CAFILE');
            $publisher->destroy();
            $project->destroy();
        }
    }

    public function testNothingCanReadAdvisoriesFromOutsideThePinWhileThePinIsInForce(): void
    {
        // Binding a run to particular bytes is only worth anything if nothing else can answer the same
        // question. An option that selects a different advisory source is not another way of honouring
        // the pin, it is ignoring it: the pin goes unchecked and a source naming no advisories reports
        // the lock clean. Whatever is added later that can answer "which advisories apply", it belongs
        // in this list.
        $project = new ScriptedProject(['acme/lib' => '^1'], [['acme/lib', '1.0.0']]);
        try {
            $path = $project->directory . '/verified.sqlite';
            (new DatabaseWriter())->write([self::advisory()], [], $path);
            $digest = hash_file('sha256', $path);
            self::assertIsString($digest);
            $runner = new CommandRunner();
            $pinned = ['--database-location' => $path, '--database-sha256' => $digest];

            // With the pin alone the advisory is found, which is what the alternatives must not undo.
            $control = $runner->run(['command' => 'remediate', '--format' => 'json'] + $pinned, $project->directory);
            self::assertSame(2, $control->exitCode, $control->describe());

            $empty = $project->directory . '/empty.json';
            file_put_contents($empty, '{"advisories":{}}');
            $elsewhere = [
                'a file of advisories' => ['--advisories-file' => $empty],
                'the configured repositories' => ['--no-database' => true],
            ];
            foreach ($elsewhere as $what => $option) {
                foreach ([[], ['--apply' => true]] as $extra) {
                    $run = $runner->run(['command' => 'remediate', '--format' => 'json'] + $option + $extra + $pinned, $project->directory);
                    self::assertSame(
                        4,
                        $run->exitCode,
                        sprintf('%s answered instead of the pinned database%s', $what, $extra === [] ? '' : ', while applying') . "\n" . $run->describe(),
                    );
                }
            }
        } finally {
            $project->destroy();
        }
    }

    public function testTheActionPinsEveryCommandToWhatItVerified(): void
    {
        // The action is the path most adopters take, and it is bash rather than PHP, so the guarantee
        // is checked where it is written: the digest it computes has to reach every command it runs,
        // and the flags that carry it have to come after the caller's own arguments so that an
        // argument naming another source cannot quietly select one that was never verified.
        $script = file_get_contents(__DIR__ . '/../../action/run.sh');
        self::assertIsString($script);

        self::assertStringContainsString('gh attestation verify', $script);
        self::assertMatchesRegularExpression('{database_digest="\$\(sha256sum [^)]+\)"}', $script, 'the action has to know the digest of what it verified');
        self::assertMatchesRegularExpression('{REMEDIATE_ARGS="\$\{REMEDIATE_ARGS:-\}[^"]*--database-sha256=\$database_digest"}', $script, 'the digest has to be appended after the caller arguments, not before them');

        $applied = [];
        foreach (explode("\n", $script) as $line) {
            if (str_contains($line, 'composer remediate') && str_contains($line, '$REMEDIATE_ARGS')) {
                $applied[] = trim($line);
            }
        }
        self::assertGreaterThanOrEqual(2, count($applied), 'both the planning run and the applying run have to carry the pin');
    }

    private static function advisory(): \Remediate\Engine\Advisory\Db\NormalizedAdvisory
    {
        return new \Remediate\Engine\Advisory\Db\NormalizedAdvisory(
            'CVE-2026-0002',
            ['CVE-2026-0002'],
            'Synthetic',
            null,
            'high',
            null,
            null,
            [new \Remediate\Engine\Advisory\Db\AffectedRange('acme/lib', '<2.0.0', 'contract')],
            [new \Remediate\Engine\Advisory\Db\SourceRecord('contract', 'CVE-2026-0002')],
        );
    }

    /**
     * Invariant: the database a worker reads after forking is the database this run verified.
     *
     * Eighth adversarial review, finding 4. Parallel planning forks, and a SQLite handle cannot be
     * carried across a fork, so each child reopens the file. Reopening named the path, and a path is
     * not a file: a cache refresh landing between the run's verification and that call — a concurrent
     * process, or this tool's own download — put a different database there and the child read it as
     * the verified one. An earlier --database-sha256 check does not reach a connection opened later.
     * The probe found one advisory through the original connection and none after replacement.
     *
     * This contract already checked verification between commands; the gap was replacement during one.
     */
    public function testAWorkerRefusesADatabaseThatWasReplacedAfterTheRunVerifiedIt(): void
    {
        $dir = sys_get_temp_dir() . '/composer-remediate-fork-' . bin2hex(random_bytes(4));
        mkdir($dir, 0700, true);
        $path = $dir . '/advisories.sqlite';

        try {
            (new DatabaseWriter())->write([self::advisoryFor('acme/lib')], [], $path);
            $database = Database::open($path);
            $provider = new SqliteAdvisoryProvider($database);
            self::assertNotSame([], $provider->advisoriesFor(['acme/lib']), 'the verified database answers');

            // What a concurrent refresh does: same path, different database.
            (new DatabaseWriter())->write([], [], $dir . '/replacement.sqlite');
            rename($dir . '/replacement.sqlite', $path);

            $this->expectException(AdvisoryLookupFailed::class);
            $this->expectExceptionMessageMatches('{was replaced while this run was using it}');
            $provider->afterFork();
        } finally {
            foreach (glob($dir . '/*') ?: [] as $file) {
                @unlink($file);
            }
            @rmdir($dir);
        }
    }

    private static function advisoryFor(string $package): NormalizedAdvisory
    {
        return new NormalizedAdvisory(
            'TEST-FORK-1',
            ['TEST-FORK-1'],
            'Synthetic',
            null,
            'high',
            null,
            null,
            [new AffectedRange($package, '<2.0.0', 'test')],
            [],
        );
    }
}
