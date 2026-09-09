<?php

declare(strict_types=1);

namespace Remediate\Tests\Integration;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Remediate\Engine\Plan\FindingPlan;
use Remediate\Output\TextRenderer;
use Remediate\Tests\Support\FixtureRunner;

/**
 * Every directory under tests/Fixture with an expected.json is a test case. expected.json:
 *
 *   {
 *     "description": "...",
 *     "platform": {"php": "8.3.0"},                 optional config.platform overrides
 *     "findings": [
 *       {
 *         "package": "symfony/http-foundation",
 *         "advisory": "PKSA-...",                     advisory id or CVE
 *         "remediation": true,                        whether a verified remediation must exist
 *         "command": "composer update ... -W -m ...", exact recommended command (with -m)
 *         "max_changes": 3,                           optional upper bound on changed packages
 *         "target_version": "6.4.24"                  optional expected version of the package after the fix
 *       }
 *     ]
 *   }
 */
final class FixtureTest extends TestCase
{
    private FixtureRunner $runner;

    protected function setUp(): void
    {
        $this->runner = new FixtureRunner();
    }

    protected function tearDown(): void
    {
        $this->runner->cleanup();
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function fixtures(): iterable
    {
        foreach (FixtureRunner::all() as $dir) {
            yield basename($dir) => [$dir];
        }
    }

    #[DataProvider('fixtures')]
    public function testFixture(string $fixtureDir): void
    {
        $expected = FixtureRunner::expected($fixtureDir);
        $plan = $this->runner->run($fixtureDir, (bool) ($expected['allow_direct_require'] ?? false));
        $rendered = (new TextRenderer())->render($plan);

        $expectedFindings = $expected['findings'] ?? [];
        self::assertIsArray($expectedFindings);
        self::assertCount(count($expectedFindings), $plan->findings, "Unexpected number of findings.\n$rendered");

        foreach ($expectedFindings as $exp) {
            self::assertIsArray($exp);
            $package = $exp['package'];
            $advisory = $exp['advisory'];
            self::assertIsString($package);
            self::assertIsString($advisory);
            $findingPlan = self::findingFor($plan->findings, $package, $advisory);
            self::assertNotNull($findingPlan, "No finding for $advisory on $package.\n$rendered");

            $mustRemediate = (bool) ($exp['remediation'] ?? true);
            self::assertSame($mustRemediate, $findingPlan->hasRemediation(), ($mustRemediate ? 'Expected a remediation' : 'Expected no remediation') . " for $advisory on $package.\n$rendered");
            if (!$mustRemediate) {
                continue;
            }
            $recommended = $findingPlan->recommended();
            self::assertNotNull($recommended);
            if (isset($exp['command'])) {
                self::assertSame($exp['command'], $recommended->candidate->commandLine(true), "Recommended command differs.\n$rendered");
            }
            if (isset($exp['max_changes'])) {
                self::assertLessThanOrEqual($exp['max_changes'], $recommended->diff?->count(), "Too many changes.\n$rendered");
            }
            if (isset($exp['target_version'])) {
                self::assertSame($exp['target_version'], $recommended->result->after?->get($package)?->getPrettyVersion(), "Unexpected version after remediation.\n$rendered");
            }
        }
    }

    /**
     * @param list<FindingPlan> $plans
     */
    private static function findingFor(array $plans, string $package, string $advisory): ?FindingPlan
    {
        foreach ($plans as $plan) {
            $f = $plan->finding;
            if ($f->packageName === $package && ($f->advisory->id === $advisory || $f->advisory->cve === $advisory)) {
                return $plan;
            }
        }

        return null;
    }
}
