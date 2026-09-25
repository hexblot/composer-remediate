<?php

declare(strict_types=1);

namespace Remediate\Tests\Unit\Output;

use JsonSchema\Validator;
use PHPUnit\Framework\TestCase;
use Remediate\Engine\Matching\Finding;
use Remediate\Engine\Plan\FindingPlan;
use Remediate\Engine\Plan\Plan;
use Remediate\Output\HtmlRenderer;
use Remediate\Output\JsonRenderer;
use Remediate\Output\TextRenderer;
use Remediate\Tests\Support\ScriptedProject;

/**
 * --exposed: a package the operator says handles untrusted input is listed first, and nothing else
 * about the run changes.
 */
final class DeclaredExposureTest extends TestCase
{
    /**
     * In the planner's urgency order: known exploited, critical, medium, then a development-only finding.
     */
    private static function plan(): Plan
    {
        $kev = new Finding(ScriptedProject::advisory('PKSA-1', 'dompdf/dompdf', '<3.0.0', 'medium', null, 0.5, '2026-02-01'), 'dompdf/dompdf', '2.0.0.0', '2.0.0', false, true);
        $critical = new Finding(ScriptedProject::advisory('PKSA-2', 'acme/other', '<2.0.0', 'critical'), 'acme/other', '1.5.0.0', '1.5.0', false, false);
        $guzzle = new Finding(ScriptedProject::advisory('PKSA-3', 'guzzlehttp/psr7', '<2.0.0', 'medium'), 'guzzlehttp/psr7', '1.9.0.0', '1.9.0', false, false);
        $dev = new Finding(ScriptedProject::advisory('PKSA-4', 'acme/tool', '<2.0.0', 'high'), 'acme/tool', '1.0.0.0', '1.0.0', true, true);

        return new Plan(
            array_map(static fn (Finding $f): FindingPlan => new FindingPlan($f, [], []), [$kev, $critical, $guzzle, $dev]),
            ['project' => '/p', 'advisory_source' => 'scripted', 'solver' => 'fake'],
            [],
            null,
            null,
            array_map(static fn (string $n): array => ['name' => $n, 'version' => '1.0.0', 'dev' => false], ['dompdf/dompdf', 'acme/other', 'guzzlehttp/psr7', 'acme/tool']),
        );
    }

    /** @return list<string> */
    private static function order(Plan $plan): array
    {
        return array_map(static fn (FindingPlan $p): string => $p->finding->packageName, $plan->findings);
    }

    public function testAnExposedPackageComesFirstAndTheRestKeepTheirOrder(): void
    {
        $plan = self::plan()->withExposure(['GuzzleHttp/Psr7']);

        self::assertSame(['guzzlehttp/psr7', 'dompdf/dompdf', 'acme/other', 'acme/tool'], self::order($plan));
        self::assertSame(['guzzlehttp/psr7'], array_map(static fn (FindingPlan $p): string => $p->finding->packageName, $plan->exposedFindings()));
        self::assertSame([], $plan->warnings);
    }

    public function testADevelopmentFindingStaysBehindProductionEvenWhenDeclared(): void
    {
        $plan = self::plan()->withExposure(['acme/tool']);

        self::assertSame(['dompdf/dompdf', 'acme/other', 'guzzlehttp/psr7', 'acme/tool'], self::order($plan));
        self::assertTrue($plan->isExposed($plan->findings[3]));
    }

    public function testTheReplacedNameCountsAsTheDeclaration(): void
    {
        $viaReplace = new Finding(ScriptedProject::advisory('PKSA-5', 'symfony/http-foundation', '<5.0.0', 'low'), 'symfony/symfony', '4.4.0.0', '4.4.0', false, true, 'symfony/http-foundation');
        $plan = (new Plan([...self::plan()->findings, new FindingPlan($viaReplace, [], [])], []))->withExposure(['symfony/http-foundation']);

        self::assertSame('symfony/symfony', $plan->findings[0]->finding->packageName);
    }

    public function testANameNotInTheLockIsReported(): void
    {
        $plan = self::plan()->withExposure(['guzzlehttp/psr7', 'guzzle/guzzle']);

        self::assertSame(['--exposed names guzzle/guzzle, which is not in this lock.'], $plan->warnings);
    }

    public function testNothingButTheOrderChanges(): void
    {
        $before = self::plan()->withFailOn('high');
        $after = $before->withExposure(['guzzlehttp/psr7', 'acme/tool']);

        self::assertSame($before->exitCode(), $after->exitCode());
        self::assertSame($before->combined, $after->combined);
        $strip = static function (Plan $plan): array {
            $data = json_decode((new JsonRenderer())->render($plan), true, 512, JSON_THROW_ON_ERROR);
            self::assertIsArray($data);
            unset($data['summary']['packages_declared_exposed']);
            $findings = array_map(static function (array $f): array {
                unset($f['declared_exposed']);

                return $f;
            }, $data['findings']);
            usort($findings, static fn (array $a, array $b): int => strcmp($a['package'], $b['package']));
            $data['findings'] = $findings;
            sort($data['unsolved_findings']);

            return $data;
        };
        self::assertSame($strip($before), $strip($after));
    }

    public function testEveryReportSaysWhyThePackageIsFirst(): void
    {
        $plan = self::plan()->withExposure(['guzzlehttp/psr7']);

        $text = (new TextRenderer())->render($plan);
        self::assertStringContainsString('Declared exposed: 1 package listed first because --exposed says it handles untrusted input here (guzzlehttp/psr7).', $text);
        self::assertSame(1, substr_count($text, '[declared exposed]'));

        $html = (new HtmlRenderer())->render($plan);
        self::assertSame(1, substr_count($html, '<span class="badge exposed">exposed</span>'));
        self::assertStringContainsString('Declared exposed with --exposed: it handles untrusted input in this application.', $html);

        $json = (new JsonRenderer())->render($plan);
        $data = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($data);
        self::assertSame(1, $data['summary']['packages_declared_exposed']);
        self::assertSame([true, false, false, false], array_column($data['findings'], 'declared_exposed'));
        $schemaPath = realpath(__DIR__ . '/../../../docs/schema/report.schema.json');
        self::assertNotFalse($schemaPath);
        $validator = new Validator();
        $document = json_decode($json);
        $validator->validate($document, (object) ['$ref' => 'file://' . $schemaPath]);
        self::assertTrue($validator->isValid(), implode("\n", array_map(static fn (array $e): string => sprintf('%s: %s', $e['property'], $e['message']), $validator->getErrors())));
    }

    public function testWithoutADeclarationTheReportIsUnchanged(): void
    {
        $text = (new TextRenderer())->render(self::plan());
        self::assertStringNotContainsString('exposed', $text);
    }
}
