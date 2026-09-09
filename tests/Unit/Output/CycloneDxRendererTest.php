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
use Remediate\Output\CycloneDxRenderer;
use Remediate\Output\ReportFormat;

final class CycloneDxRendererTest extends TestCase
{
    public function testPurl(): void
    {
        self::assertSame('pkg:composer/symfony/http-foundation@6.4.24', CycloneDxRenderer::purl('symfony/http-foundation', 'v6.4.24'));
        self::assertSame('pkg:composer/acme/lib@1.0.0-beta1', CycloneDxRenderer::purl('acme/lib', '1.0.0-beta1'));
    }

    public function testBomStructure(): void
    {
        $parser = new VersionParser();
        $advisory = new Advisory('GHSA-xxxx-yyyy-zzzz', 'acme/lib', $parser->parseConstraints('<1.5.0'), 'Bad thing', 'CVE-2026-1', 'https://example.test/a', 'high', new \DateTimeImmutable('2026-01-02T00:00:00Z'));
        $finding = new Finding($advisory, 'acme/lib', '1.4.0.0', '1.4.0', false, true);
        $candidate = new Candidate(Strategy::LockRefresh, ['acme/lib'], Request::UPDATE_ONLY_LISTED, [], false, [], 'x');
        $before = LockSnapshot::fromPackages([new Package('acme/lib', '1.4.0.0', '1.4.0')], []);
        $after = LockSnapshot::fromPackages([new Package('acme/lib', '1.5.0.0', '1.5.0')], []);
        $evaluated = new EvaluatedCandidate($candidate, new SolveResult(SolveStatus::Resolved, $after, ''), LockDiff::between($before, $after), true, null);
        $plan = new Plan(
            [new FindingPlan($finding, [$evaluated], [$evaluated])],
            ['engine_version' => '0.3.0-test', 'composer_version' => '2.10.3'],
            [],
            null,
            null,
            [['name' => 'acme/lib', 'version' => '1.4.0', 'dev' => false], ['name' => 'acme/dev-tool', 'version' => 'v2.0.0', 'dev' => true]],
        );

        $bom = json_decode((new CycloneDxRenderer(true, 'urn:uuid:00000000-0000-4000-8000-000000000000', '2026-01-01T00:00:00+00:00'))->render($plan), true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($bom);
        self::assertSame('CycloneDX', $bom['bomFormat']);
        self::assertSame('1.6', $bom['specVersion']);
        self::assertSame('urn:uuid:00000000-0000-4000-8000-000000000000', $bom['serialNumber']);
        self::assertCount(2, $bom['components']);
        self::assertSame('pkg:composer/acme/lib@1.4.0', $bom['components'][0]['bom-ref']);
        self::assertSame('required', $bom['components'][0]['scope']);
        self::assertSame('excluded', $bom['components'][1]['scope']);
        self::assertCount(1, $bom['vulnerabilities']);
        $vuln = $bom['vulnerabilities'][0];
        self::assertSame('GHSA-xxxx-yyyy-zzzz', $vuln['id']);
        self::assertSame('GitHub', $vuln['source']['name']);
        self::assertSame('high', $vuln['ratings'][0]['severity']);
        self::assertSame('Run: composer update acme/lib', $vuln['recommendation']);
        self::assertSame('pkg:composer/acme/lib@1.4.0', $vuln['affects'][0]['ref']);
        self::assertSame('CVE-2026-1', $vuln['references'][0]['id']);
        self::assertSame('2026-01-02T00:00:00+00:00', $vuln['published']);
        self::assertSame('exploitable', $vuln['analysis']['state']);
        self::assertSame('composer-remediate', $bom['metadata']['tools']['components'][0]['name']);
    }

    public function testOutputSpecRecognisesCycloneDx(): void
    {
        self::assertSame([ReportFormat::CycloneDx, 'sbom.cdx.json'], ReportFormat::parseOutputSpec('sbom.cdx.json'));
        self::assertSame([ReportFormat::CycloneDx, 'build/bom.json'], ReportFormat::parseOutputSpec('build/bom.json'));
        self::assertSame([ReportFormat::CycloneDx, 'x.json'], ReportFormat::parseOutputSpec('cyclonedx:x.json'));
        self::assertSame([ReportFormat::Json, 'report.json'], ReportFormat::parseOutputSpec('report.json'));
    }
}
