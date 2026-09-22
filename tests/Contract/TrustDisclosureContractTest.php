<?php

declare(strict_types=1);

namespace Remediate\Tests\Contract;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Remediate\Output\ReportFormat;
use Remediate\Tests\Support\CommandRunner;
use Remediate\Tests\Support\ScriptedProject;

/**
 * Invariant: whatever reduced what a run could see, or was taken on trust to produce it, is disclosed
 * in every format that has somewhere to put it.
 *
 * Eighth adversarial review, finding 7. A warning is the difference between "no vulnerabilities" and
 * "no vulnerabilities that this run was allowed to see". The clearest case is the analysed project
 * suppressing advisories through its own `config.audit.ignore`: the exit code is 0 and the
 * vulnerability list is empty, and only the warning says the emptiness is the project's doing. That
 * warning reached text, HTML, JSON, SARIF and GitLab, and not CycloneDX — the one format whose whole
 * purpose is to be filed and trusted later.
 *
 * This is a contract rather than a renderer test because the defect was divergence: each format was
 * right on its own terms and the set of them was not.
 */
final class TrustDisclosureContractTest extends TestCase
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
    public function testASuppressionByTheAnalysedProjectIsDisclosed(ReportFormat $format): void
    {
        $project = new ScriptedProject(['acme/lib' => '^1'], [['acme/lib', '1.0.0']]);
        try {
            // The project excuses its own advisory. The run is complete and exits 0; what it does not
            // get to do is present that as a clean result with no explanation.
            CommandRunner::editComposerJson($project->directory, static function (array $json): array {
                $json['config']['audit']['ignore'] = ['TEST-1'];

                return $json;
            });
            $advisories = $project->directory . '/advisories.json';
            file_put_contents($advisories, (string) json_encode(['advisories' => ['acme/lib' => [[
                'advisoryId' => 'TEST-1',
                'packageName' => 'acme/lib',
                'affectedVersions' => '<2.0.0',
                'title' => 'Suppressed by the project',
            ]]]]));

            $run = (new CommandRunner())->run([
                'command' => 'remediate',
                '--format' => $format->value,
                '--advisories-file' => $advisories,
            ], $project->directory);

            self::assertSame(0, $run->exitCode, $run->describe());
            self::assertMatchesRegularExpression(
                '{config\.audit\.ignore|suppress}i',
                $run->stdout,
                sprintf('%s does not disclose that the analysed project suppressed an advisory: %s', $format->value, $run->describe()),
            );
        } finally {
            $project->destroy();
        }
    }
}
