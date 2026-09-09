<?php

declare(strict_types=1);

namespace Remediate\Tests\Unit\Output;

use Composer\DependencyResolver\Request;
use Composer\Package\Package;
use Composer\Semver\VersionParser;
use PHPUnit\Framework\TestCase;
use Remediate\Engine\Advisory\Advisory;
use Remediate\Engine\Candidate\Candidate;
use Remediate\Engine\Candidate\Strategy;
use Remediate\Engine\Lock\LockSnapshot;
use Remediate\Engine\Matching\Finding;
use Remediate\Engine\Plan\EvaluatedCandidate;
use Remediate\Engine\Plan\FindingPlan;
use Remediate\Engine\Plan\Plan;
use Remediate\Engine\Solver\LockDiff;
use Remediate\Engine\Solver\SolveResult;
use Remediate\Engine\Solver\SolveStatus;
use Remediate\Output\LockLineIndex;
use Remediate\Output\ReportFormat;
use Remediate\Output\SarifRenderer;

final class SarifRendererTest extends TestCase
{
    private function plan(): Plan
    {
        $parser = new VersionParser();
        $high = new Advisory('PKSA-aaaa', 'acme/lib', $parser->parseConstraints('<1.5.0'), 'Bad thing', 'CVE-2026-1', 'https://example.test/a', 'high');
        $low = new Advisory('PKSA-bbbb', 'acme/tool', $parser->parseConstraints('<2.0.0'), 'Minor thing', null, null, 'low');

        $fixed = new Finding($high, 'acme/lib', '1.4.0.0', '1.4.0', false, true);
        $candidate = new Candidate(Strategy::LockRefresh, ['acme/lib'], Request::UPDATE_ONLY_LISTED, [], false, [], 'x');
        $before = LockSnapshot::fromPackages([new Package('acme/lib', '1.4.0.0', '1.4.0')], []);
        $after = LockSnapshot::fromPackages([new Package('acme/lib', '1.5.0.0', '1.5.0')], []);
        $evaluated = new EvaluatedCandidate($candidate, new SolveResult(SolveStatus::Resolved, $after, ''), LockDiff::between($before, $after), true, null);
        $unfixed = new Finding($low, 'acme/tool', '1.9.0.0', '1.9.0', true, false);

        return new Plan(
            [new FindingPlan($fixed, [$evaluated], [$evaluated]), new FindingPlan($unfixed, [], [], 'nothing newer exists')],
            ['project' => '/p', 'engine_version' => '0.3.0-test', 'composer_version' => '2.10.3'],
        );
    }

    public function testSarifStructure(): void
    {
        $lines = new LockLineIndex(['acme/lib' => 42], 'composer.lock');
        $sarif = json_decode((new SarifRenderer(true, $lines))->render($this->plan()), true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($sarif);
        self::assertSame('2.1.0', $sarif['version']);
        $run = $sarif['runs'][0];
        self::assertSame('composer-remediate', $run['tool']['driver']['name']);
        self::assertSame('0.3.0-test', $run['tool']['driver']['version']);
        self::assertCount(2, $run['tool']['driver']['rules']);
        self::assertSame('PKSA-aaaa', $run['tool']['driver']['rules'][0]['id']);
        self::assertSame('7.5', $run['tool']['driver']['rules'][0]['properties']['security-severity']);
        self::assertSame('error', $run['tool']['driver']['rules'][0]['defaultConfiguration']['level']);
        self::assertSame('note', $run['tool']['driver']['rules'][1]['defaultConfiguration']['level']);

        self::assertCount(2, $run['results']);
        $first = $run['results'][0];
        self::assertSame('PKSA-aaaa', $first['ruleId']);
        self::assertSame(0, $first['ruleIndex']);
        self::assertStringContainsString('Verified fix: composer update acme/lib', $first['message']['text']);
        self::assertSame('composer.lock', $first['locations'][0]['physicalLocation']['artifactLocation']['uri']);
        self::assertSame(42, $first['locations'][0]['physicalLocation']['region']['startLine']);
        self::assertSame('verified', $first['properties']['remediation_status']);

        $second = $run['results'][1];
        self::assertStringContainsString('No verified remediation found (nothing newer exists)', $second['message']['text']);
        self::assertArrayNotHasKey('region', $second['locations'][0]['physicalLocation'], 'unknown line: no region');
        self::assertSame(2, $run['invocations'][0]['exitCode']);
    }

    public function testFailOnThresholdGatesTheExitCode(): void
    {
        $plan = $this->plan();
        self::assertSame(Plan::EXIT_NO_REMEDIATION, $plan->exitCode(), 'the low finding without a fix drives the code');
        self::assertSame(Plan::EXIT_REMEDIATION_AVAILABLE, $plan->withFailOn('medium')->exitCode(), 'low finding no longer counts');
        self::assertSame(Plan::EXIT_REMEDIATION_AVAILABLE, $plan->withFailOn('high')->exitCode());
        self::assertSame(Plan::EXIT_CLEAN, $plan->withFailOn('critical')->exitCode());
        self::assertCount(1, $plan->withFailOn('high')->gated());
        $this->expectException(\InvalidArgumentException::class);
        $plan->withFailOn('severe');
    }

    public function testOutputSpecRecognisesSarif(): void
    {
        self::assertSame([ReportFormat::Sarif, 'out/results.sarif'], ReportFormat::parseOutputSpec('out/results.sarif'));
        self::assertSame([ReportFormat::Sarif, 'results.sarif.json'], ReportFormat::parseOutputSpec('results.sarif.json'));
        self::assertSame([ReportFormat::Sarif, 'x'], ReportFormat::parseOutputSpec('sarif:x'));
    }
}
