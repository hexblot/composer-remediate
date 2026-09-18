<?php

declare(strict_types=1);

namespace Remediate\Tests\Contract;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Remediate\Engine\Advisory\Db\CoverageGap;
use Remediate\Engine\Advisory\Db\DatabaseWriter;
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
                // Written for a person, so the requirement is that the reason is in front of them.
                self::assertStringContainsString('UNREADABLE-RECORD', $output, $describe);
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
}
