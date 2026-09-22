<?php

declare(strict_types=1);

namespace Remediate\Tests\Contract;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Remediate\Engine\Advisory\Db\CoverageGap;
use Remediate\Engine\Advisory\Db\DatabaseWriter;
use Remediate\Engine\Plan\Plan;
use Remediate\Output\ReportFormat;
use Remediate\Tests\Support\CommandRunner;
use Remediate\Tests\Support\ScriptedProject;

/**
 * Invariant: a run that could not establish what it set out to establish never reads as successful,
 * in any format that has a way to say so.
 *
 * Exit codes 3, 4 and 5 mean the tool could not answer: a tool error, advisory data it could not
 * read, package metadata it could not fetch. Exit codes 0, 1 and 2 are complete answers, findings
 * included. The formats disagreeing about that is the danger, because each one is read by a different
 * consumer: an empty vulnerability list on a successful invocation is a clean bill of health to a
 * dashboard, whatever the exit code the pipeline never looked at.
 */
final class ReportStatusContractTest extends TestCase
{
    /** @return iterable<string, array{ReportFormat}> */
    public static function formats(): iterable
    {
        foreach (ReportFormat::cases() as $format) {
            if ($format !== ReportFormat::None) {
                yield $format->value => [$format];
            }
        }
    }

    #[DataProvider('formats')]
    public function testAnIncompleteRunIsNeverPresentedAsSuccessful(ReportFormat $format): void
    {
        $project = new ScriptedProject(['acme/lib' => '^1'], [['acme/lib', '1.0.0']]);
        try {
            // A database whose only content is a record it could not read: nothing to report against
            // the lock, and no basis for calling the lock clean either.
            $path = $project->directory . '/gaps.sqlite';
            (new DatabaseWriter())->write([], [], $path, [], [new CoverageGap('OSV', 'UNREADABLE-RECORD', 'acme/lib', 'unreadable range')]);
            $run = (new CommandRunner())->run(['command' => 'remediate', '--format' => $format->value, '--database-location' => $path], $project->directory);

            self::assertSame(4, $run->exitCode, $run->describe());
            $this->assertFormatSaysTheRunFailed($format, $run->stdout, $run->describe());
            if ($format === ReportFormat::Text || $format === ReportFormat::Html) {
                self::assertStringContainsString('UNREADABLE-RECORD', $run->stdout, 'the unreadable record is named, not just counted' . "\n" . $run->describe());
            }
        } finally {
            $project->destroy();
        }
    }

    #[DataProvider('formats')]
    public function testACompleteRunWithFindingsIsStillASuccessfulRun(ReportFormat $format): void
    {
        // The other half: findings are the answer, not a failure. A format that marked every run with
        // a finding as failed would satisfy the test above and be useless.
        $project = new ScriptedProject(['acme/lib' => '^1'], [['acme/lib', '1.0.0']]);
        try {
            $path = $project->directory . '/findings.sqlite';
            (new DatabaseWriter())->write([self::advisory()], [], $path);
            $run = (new CommandRunner())->run(['command' => 'remediate', '--format' => $format->value, '--database-location' => $path], $project->directory);

            self::assertContains($run->exitCode, [1, 2], $run->describe());
            if ($format === ReportFormat::Sarif) {
                self::assertTrue($run->json()['runs'][0]['invocations'][0]['executionSuccessful'], $run->describe());
            }
            if ($format === ReportFormat::GitLab) {
                self::assertSame('success', $run->json()['scan']['status'], $run->describe());
            }
            if ($format === ReportFormat::CycloneDx) {
                $properties = [];
                foreach ($run->json()['metadata']['properties'] ?? [] as $property) {
                    $properties[$property['name']] = $property['value'];
                }
                self::assertSame('complete', $properties['composer-remediate:scan_status'] ?? null, $run->describe());
            }
        } finally {
            $project->destroy();
        }
    }

    private function assertFormatSaysTheRunFailed(ReportFormat $format, string $output, string $describe): void
    {
        switch ($format) {
            case ReportFormat::Sarif:
                $report = json_decode($output, true, 512, JSON_THROW_ON_ERROR);
                self::assertIsArray($report);
                self::assertFalse($report['runs'][0]['invocations'][0]['executionSuccessful'], $describe);
                self::assertNotSame([], $report['runs'][0]['invocations'][0]['toolExecutionNotifications'] ?? [], 'a failed invocation has to say why' . "\n" . $describe);
                break;
            case ReportFormat::GitLab:
                $report = json_decode($output, true, 512, JSON_THROW_ON_ERROR);
                self::assertIsArray($report);
                self::assertSame('failure', $report['scan']['status'], $describe);
                break;
            case ReportFormat::Json:
                $report = json_decode($output, true, 512, JSON_THROW_ON_ERROR);
                self::assertIsArray($report);
                self::assertSame(4, $report['exit_code'], $describe);
                self::assertNotSame([], $report['warnings'], $describe);
                break;
            case ReportFormat::CycloneDx:
                // A bill of materials has no status field of its own, so the standard extension point
                // carries it: an empty vulnerability list must not be the only thing a consumer sees.
                $report = json_decode($output, true, 512, JSON_THROW_ON_ERROR);
                self::assertIsArray($report);
                $properties = [];
                foreach ($report['metadata']['properties'] ?? [] as $property) {
                    $properties[$property['name']] = $property['value'];
                }
                self::assertSame('incomplete', $properties['composer-remediate:scan_status'] ?? null, $describe);
                self::assertNotSame('', $properties['composer-remediate:scan_incomplete_reason'] ?? '', $describe);
                break;
            case ReportFormat::Text:
            case ReportFormat::Html:
                // Written for a person, so the requirement is that the reason is in front of them. It
                // used to be enough that a record identifier appeared somewhere, which only held for
                // the one scenario this contract started with and said nothing about a run that failed
                // before it had anything to name. What has to be there is that the run did not answer.
                self::assertStringContainsString('Scan failed', $output, $describe);
                self::assertStringNotContainsString('No known vulnerabilities in the locked dependencies.', $output, 'a failed run borrowed the sentence for a clean one' . "\n" . $describe);
                break;
            default:
                self::fail('no status expectation stated for ' . $format->value . '; every format needs one');
        }
    }

    private static function advisory(): \Remediate\Engine\Advisory\Db\NormalizedAdvisory
    {
        return new \Remediate\Engine\Advisory\Db\NormalizedAdvisory(
            'CVE-2026-0001',
            ['CVE-2026-0001'],
            'Synthetic',
            null,
            'high',
            null,
            null,
            [new \Remediate\Engine\Advisory\Db\AffectedRange('acme/lib', '<2.0.0', 'contract')],
            [new \Remediate\Engine\Advisory\Db\SourceRecord('contract', 'CVE-2026-0001')],
        );
    }

    /**
     * Eighth adversarial review, finding 3. The contract above starts from a database that loaded and
     * had gaps, so it only ever covered failures that still produced a plan. A failure before a plan
     * exists used to return before anything was rendered, which left the previous run's `--output`
     * file untouched on disk — and a CI step that uploads that file then published a stale clean
     * result for a scan that never ran. Silence is the dangerous outcome here, not a bad report.
     */
    #[DataProvider('formats')]
    public function testAFailureBeforeAPlanExistsStillReplacesTheReportItWasAskedFor(ReportFormat $format): void
    {
        $project = new ScriptedProject(['acme/lib' => '^1'], [['acme/lib', '1.0.0']]);
        try {
            $runner = new CommandRunner();
            $report = $project->directory . '/scan.out';
            // The format is named by prefix, so every format writes to one path with no extension rules.
            $target = $format->value . ':' . $report;
            $advisories = $project->directory . '/advisories.json';
            file_put_contents($advisories, (string) json_encode(['advisories' => []]));

            $clean = $runner->run([
                'command' => 'remediate',
                '--format' => 'none',
                '--advisories-file' => $advisories,
                '--output' => [$target],
            ], $project->directory);
            self::assertSame(0, $clean->exitCode, $clean->describe());
            $successful = (string) file_get_contents($report);
            self::assertNotSame('', $successful);

            // The same command, with advisory data it cannot read.
            file_put_contents($advisories, '{ this is not json');
            $failed = $runner->run([
                'command' => 'remediate',
                '--format' => $format->value,
                '--advisories-file' => $advisories,
                '--output' => [$target],
            ], $project->directory);

            self::assertSame(4, $failed->exitCode, $failed->describe());
            self::assertNotSame($successful, (string) file_get_contents($report), sprintf('the %s report from the previous successful run survived a failed one', $format->value));
            $this->assertFormatSaysTheRunFailed($format, (string) file_get_contents($report), $failed->describe());
            $this->assertFormatSaysTheRunFailed($format, $failed->stdout, $failed->describe());
        } finally {
            $project->destroy();
        }
    }

    /**
     * Recheck of the eighth review, finding 2. The test above covers one way to fail — advisory data
     * that will not parse. It passed while three others still returned before rendering: a corrupt
     * baseline, an invalid --fail-on, and an advisory database missing a table. The last escaped as an
     * uncaught exception, which Symfony turns into exit 1: the code for "vulnerabilities, every one
     * with a verified fix". The shipped action read that as success and carried on.
     *
     * The trigger is not the point; that a failure writes its report is. So this states it once over
     * every way in.
     *
     * @return iterable<string, array{callable(string): array<string, mixed>, int}>
     */
    public static function failureTriggers(): iterable
    {
        yield 'advisory data that will not parse' => [static function (string $dir): array {
            file_put_contents($dir . '/advisories.json', '{ this is not json');

            return ['--advisories-file' => $dir . '/advisories.json'];
        }, 4];

        yield 'a corrupt baseline' => [static function (string $dir): array {
            file_put_contents($dir . '/advisories.json', (string) json_encode(['advisories' => []]));
            file_put_contents($dir . '/baseline.json', '{ not a baseline');

            return ['--advisories-file' => $dir . '/advisories.json', '--baseline' => $dir . '/baseline.json'];
        }, 3];

        yield 'a severity that is not one' => [static function (string $dir): array {
            file_put_contents($dir . '/advisories.json', (string) json_encode(['advisories' => []]));

            return ['--advisories-file' => $dir . '/advisories.json', '--fail-on' => 'catastrophic'];
        }, 3];

        yield 'an advisory database missing a table' => [static function (string $dir): array {
            $path = $dir . '/broken.sqlite';
            (new DatabaseWriter())->write([], [], $path);
            $pdo = new \PDO('sqlite:' . $path);
            $pdo->exec('DROP TABLE affected');
            $pdo = null;

            return ['--database-location' => $path];
        }, 4];
    }

    /**
     * @param callable(string): array<string, mixed> $arrange
     */
    #[DataProvider('failureTriggers')]
    public function testEveryWayOfFailingStillReplacesTheReport(callable $arrange, int $expectedExit): void
    {
        $project = new ScriptedProject(['acme/lib' => '^1'], [['acme/lib', '1.0.0']]);
        try {
            $runner = new CommandRunner();
            $report = $project->directory . '/scan.out';
            $clean = $project->directory . '/clean-advisories.json';
            file_put_contents($clean, (string) json_encode(['advisories' => []]));

            $first = $runner->run([
                'command' => 'remediate',
                '--format' => 'none',
                '--advisories-file' => $clean,
                '--output' => ['sarif:' . $report],
            ], $project->directory);
            self::assertSame(0, $first->exitCode, $first->describe());
            $successful = (string) file_get_contents($report);

            $failed = $runner->run([
                'command' => 'remediate',
                '--format' => 'sarif',
                '--output' => ['sarif:' . $report],
            ] + $arrange($project->directory), $project->directory);

            self::assertSame($expectedExit, $failed->exitCode, $failed->describe());
            self::assertNotSame($successful, (string) file_get_contents($report), 'the previous successful report survived a failed run');
            $this->assertFormatSaysTheRunFailed(ReportFormat::Sarif, (string) file_get_contents($report), $failed->describe());
        } finally {
            $project->destroy();
        }
    }

    /**
     * Invariant: one destination that cannot be written decides nothing for the destinations that can.
     *
     * Second recheck of the eighth review. `emit()` returned at the first output it could not write,
     * skipping every later one and stdout with them. A path under a directory that does not exist, or a
     * full disk, was therefore enough to leave a second `--output` holding the last successful run's
     * report — and a CI artifact step goes on publishing that clean result for a run that failed. The
     * unwritable destination still makes the run a tool error; it does not get to speak for the others.
     */
    public function testAnUnwritableDestinationDoesNotLeaveTheOthersStale(): void
    {
        $project = new ScriptedProject(['acme/lib' => '^1'], [['acme/lib', '1.0.0']]);
        try {
            $runner = new CommandRunner();
            $report = $project->directory . '/scan.sarif';
            $advisories = $project->directory . '/advisories.json';
            file_put_contents($advisories, (string) json_encode(['advisories' => []]));

            $clean = $runner->run([
                'command' => 'remediate',
                '--format' => 'none',
                '--advisories-file' => $advisories,
                '--output' => ['sarif:' . $report],
            ], $project->directory);
            self::assertSame(0, $clean->exitCode, $clean->describe());
            $successful = (string) file_get_contents($report);

            // A failing run asked for two files, the first of which cannot be written, plus stdout.
            file_put_contents($project->directory . '/baseline.json', '{ not a baseline');
            $failed = $runner->run([
                'command' => 'remediate',
                '--format' => 'json',
                '--advisories-file' => $advisories,
                '--baseline' => $project->directory . '/baseline.json',
                '--output' => ['json:' . $project->directory . '/no-such-dir/scan.json', 'sarif:' . $report],
            ], $project->directory);

            self::assertSame(Plan::EXIT_ERROR, $failed->exitCode, $failed->describe());
            self::assertNotSame('', $failed->stdout, 'stdout was skipped because an earlier file could not be written');
            self::assertNotSame($successful, (string) file_get_contents($report), 'the writable report still holds the previous successful run');
            $this->assertFormatSaysTheRunFailed(ReportFormat::Sarif, (string) file_get_contents($report), $failed->describe());
        } finally {
            $project->destroy();
        }
    }
}
