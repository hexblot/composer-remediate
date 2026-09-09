<?php

declare(strict_types=1);

namespace Remediate\Tests\Integration;

use JsonSchema\Validator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Remediate\Engine\Advisory\JsonFileAdvisoryProvider;
use Remediate\Engine\Lock\LockSnapshot;
use Remediate\Engine\Matching\Matcher;
use Remediate\Engine\Plan\FindingPlan;
use Remediate\Engine\Solver\InProcessSolver;
use Remediate\Output\HtmlRenderer;
use Remediate\Output\JsonRenderer;
use Remediate\Output\TextRenderer;
use Remediate\Tests\Support\FixtureRunner;
use Symfony\Component\Process\Process;

/**
 * Every directory under tests/Fixture with an expected.json is a test case. expected.json:
 *
 *   {
 *     "description": "...",
 *     "platform": {"php": "8.3.0"},                 optional config.platform overrides
 *     "strict_findings": false,                     when true, the plan must contain exactly the listed findings
 *     "combined_command": "composer update a b",   optional: the verified command covering all fixable findings
 *     "findings": [
 *       {
 *         "package": "symfony/http-foundation",
 *         "advisory": "PKSA-...",                     advisory id or CVE
 *         "remediation": true,                        whether a verified remediation must exist
 *         "command": "composer update ... -W -m ...", exact recommended command (with -m)
 *         "max_changes": 3,                           optional upper bound on changed packages
 *         "target_version": "6.4.24"                  optional expected version of the package after the fix
 *       }
 *     ],
 *     "execute": true                               run the recommended commands with the real composer binary in a
 *                                                   scratch copy and assert the written lock is free of the findings
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
        $html = (new HtmlRenderer())->render($plan);
        self::assertStringStartsWith('<!DOCTYPE html>', $html);
        self::assertStringContainsString('</html>', $html);
        self::assertStringNotContainsString('<script', $html);
        $jsonText = (new JsonRenderer())->render($plan);
        $json = json_decode($jsonText, true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($json);
        self::assertSame($plan->exitCode(), $json['exit_code']);
        self::assertCount(count($plan->findings), $json['findings']);
        self::assertJsonMatchesSchema($jsonText);

        // Expected command strings are recorded on a Composer with --minimal-changes (2.9+). Older
        // releases cannot apply -m, so the simplification step legitimately drops it (and often the
        // --with guard); there only the outcome, target version and change count are asserted.
        $exactCommands = (new InProcessSolver())->supportsMinimalChanges();
        if (isset($expected['combined_command'])) {
            self::assertNotNull($plan->combined, "Expected a combined command.\n$rendered");
            if ($exactCommands) {
                self::assertSame($expected['combined_command'], $plan->combined->candidate->commandLine(true), "Combined command differs.\n$rendered");
            }
        }
        $expectedFindings = $expected['findings'] ?? [];
        self::assertIsArray($expectedFindings);
        if ((bool) ($expected['strict_findings'] ?? false)) {
            $actualCount = array_sum(array_map(static fn (FindingPlan $p): int => count($p->allFindings()), $plan->findings));
            self::assertSame(count($expectedFindings), $actualCount, "Unexpected number of findings.\n$rendered");
        }

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
            if (isset($exp['command']) && $exactCommands) {
                self::assertSame($exp['command'], $recommended->candidate->commandLine(true), "Recommended command differs.\n$rendered");
                self::assertStringContainsString(htmlspecialchars((string) $exp['command'], ENT_QUOTES | ENT_HTML5), $html, 'HTML report lacks the recommended command');
            }
            if (isset($exp['max_changes']) && $exactCommands) { // change counts depend on -m as well
                self::assertLessThanOrEqual($exp['max_changes'], $recommended->diff?->count(), "Too many changes.\n$rendered");
            }
            if (isset($exp['target_version'])) {
                self::assertSame($exp['target_version'], $recommended->result->after?->get($package)?->getPrettyVersion(), "Unexpected version after remediation.\n$rendered");
            }
            if ((bool) ($expected['execute'] ?? false)) {
                $this->assertCommandRemoves($fixtureDir, $recommended->candidate->commandLine($exactCommands), $findingPlan);
            }
        }
    }

    /**
     * The printed command is a promise; here it is kept: the string the user would copy is executed by
     * the real Composer binary (the same release the in-process solver used) in a scratch copy of the
     * fixture, and the lock file it writes is re-matched against the advisories.
     */
    private function assertCommandRemoves(string $fixtureDir, string $commandLine, FindingPlan $findingPlan): void
    {
        $composer = dirname(__DIR__, 2) . '/vendor/bin/composer';
        self::assertFileExists($composer, 'composer/composer must be installed as a dev dependency');
        $project = $this->runner->workspace($fixtureDir)->materialize();
        try {
            // `composer require --no-update x && composer update ...`: run each part in order, replacing
            // the leading "composer" with the dev-dependency binary and adding --no-install (the fixture's
            // dist URLs are not fetchable; resolution and the lock are unaffected).
            foreach (explode(' && ', $commandLine) as $part) {
                self::assertStringStartsWith('composer ', $part);
                $args = array_map(static fn (string $a): string => trim($a, "'"), preg_split('{\s+}', trim(substr($part, 9))) ?: []);
                $process = new Process([PHP_BINARY, $composer, ...$args, '--no-install', '--no-interaction', '--no-progress', '--no-ansi'], $project->directory(), ['COMPOSER_HOME' => (string) getenv('COMPOSER_HOME'), 'COMPOSER_CACHE_DIR' => (string) getenv('COMPOSER_CACHE_DIR'), 'COMPOSER_NO_INTERACTION' => '1'], null, 600);
                $process->run();
                self::assertSame(0, $process->getExitCode(), "`$part` failed:\n" . $process->getOutput() . $process->getErrorOutput());
            }
            $lock = json_decode((string) file_get_contents($project->directory() . '/composer.lock'), true, 512, JSON_THROW_ON_ERROR);
            self::assertIsArray($lock);
            $loader = new \Composer\Package\Loader\ArrayLoader();
            $prod = array_map($loader->load(...), is_array($lock['packages'] ?? null) ? $lock['packages'] : []);
            $dev = array_map($loader->load(...), is_array($lock['packages-dev'] ?? null) ? $lock['packages-dev'] : []);
            $after = LockSnapshot::fromPackages($prod, $dev);
            $remaining = (new Matcher(new JsonFileAdvisoryProvider($fixtureDir . '/advisories.json')))->findingKeys($after);
            foreach ($findingPlan->allFindings() as $finding) {
                self::assertArrayNotHasKey($finding->key(), $remaining, "`$commandLine` was executed but {$finding->key()} is still present in the resulting lock");
            }
            $target = $after->get($findingPlan->finding->packageName);
            self::assertSame($findingPlan->recommended()?->result->after?->get($findingPlan->finding->packageName)?->getPrettyVersion(), $target?->getPrettyVersion(), 'the executed command must land on the version the dry-run predicted');
        } finally {
            $project->destroy();
        }
    }

    private static function assertJsonMatchesSchema(string $jsonText): void
    {
        $schemaPath = realpath(__DIR__ . '/../../docs/schema/report.schema.json');
        self::assertNotFalse($schemaPath);
        $validator = new Validator();
        $data = json_decode($jsonText);
        $validator->validate($data, (object) ['$ref' => 'file://' . $schemaPath]);
        $errors = array_map(static fn (array $e): string => sprintf('%s: %s', $e['property'], $e['message']), $validator->getErrors());
        self::assertTrue($validator->isValid(), "Freshly rendered JSON violates the schema:\n" . implode("\n", $errors));
    }

    /**
     * @param list<FindingPlan> $plans
     */
    private static function findingFor(array $plans, string $package, string $advisory): ?FindingPlan
    {
        foreach ($plans as $plan) {
            foreach ($plan->allFindings() as $f) {
                if ($f->packageName === $package && ($f->advisory->id === $advisory || $f->advisory->cve === $advisory)) {
                    return $plan;
                }
            }
        }

        return null;
    }
}
