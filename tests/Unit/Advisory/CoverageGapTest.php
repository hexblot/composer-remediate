<?php

declare(strict_types=1);

namespace Remediate\Tests\Unit\Advisory;

use PHPUnit\Framework\TestCase;
use Remediate\Engine\Advisory\Db\AffectedRange;
use Remediate\Engine\Advisory\Db\CoverageGap;
use Remediate\Engine\Advisory\Db\Database;
use Remediate\Engine\Advisory\Db\DatabaseBuilder;
use Remediate\Engine\Advisory\Db\NormalizedAdvisory;
use Remediate\Engine\Advisory\Db\Source\AdvisorySourceInterface;
use Remediate\Engine\Advisory\Db\Source\JsonFileSource;
use Remediate\Engine\Advisory\Db\Source\PackagistShapeMapper;
use Remediate\Engine\Advisory\Db\SourceRecord;
use Remediate\Engine\Advisory\Db\SqliteAdvisoryProvider;
use Remediate\Engine\Plan\Plan;
use Remediate\Engine\Planner;
use Remediate\Tests\Support\FakeSolver;
use Remediate\Tests\Support\ScriptedProject;

/**
 * A record the database build cannot read must reach the consumer as a coverage gap, never as a
 * silent absence.
 */
final class CoverageGapTest extends TestCase
{
    /** @var list<string> */
    private array $files = [];

    protected function tearDown(): void
    {
        foreach ($this->files as $file) {
            @unlink($file);
        }
    }

    private function tmp(string $suffix): string
    {
        return $this->files[] = sys_get_temp_dir() . '/composer-remediate-gap-' . bin2hex(random_bytes(4)) . $suffix;
    }

    /**
     * @param list<NormalizedAdvisory> $records
     * @param list<CoverageGap>        $gaps
     */
    private function source(array $records, array $gaps): AdvisorySourceInterface
    {
        return new class($records, $gaps) implements AdvisorySourceInterface {
            /**
             * @param list<NormalizedAdvisory> $records
             * @param list<CoverageGap>        $gaps
             */
            public function __construct(private readonly array $records, private readonly array $gaps)
            {
            }

            public function name(): string
            {
                return 'Upstream';
            }

            public function fetch(callable $log): array
            {
                return $this->records;
            }

            public function gaps(): array
            {
                return $this->gaps;
            }
        };
    }

    public function testMapperReportsWhyARecordWasLeftOut(): void
    {
        $result = (new PackagistShapeMapper())->mapDocument(['advisories' => ['acme/lib' => [
            ['advisoryId' => 'OK-1', 'affectedVersions' => '<1.0'],
            ['advisoryId' => 'BAD-1', 'affectedVersions' => 'garbage !!'],
            ['advisoryId' => 'BAD-2'],
            'not-an-object',
        ]]], 'Test');
        self::assertCount(1, $result['records']);
        self::assertSame(3, $result['skipped']);
        self::assertCount(3, $result['gaps']);
        self::assertSame('BAD-1', $result['gaps'][0]->remoteId);
        self::assertSame('acme/lib', $result['gaps'][0]->package);
        self::assertStringContainsString('unparsable affectedVersions: garbage !!', $result['gaps'][0]->describe());
    }

    public function testMalformedPackageContainersAreGapsNotSilence(): void
    {
        $result = (new PackagistShapeMapper())->mapDocument(['advisories' => [
            'acme/lib' => 'upstream-error',
            'acme/ok' => [['advisoryId' => 'OK-1', 'affectedVersions' => '<1.0']],
            'acme/null' => null,
        ]], 'Test');
        self::assertCount(1, $result['records']);
        self::assertSame(2, $result['skipped']);
        self::assertCount(2, $result['gaps']);
        self::assertSame('acme/lib', $result['gaps'][0]->package, 'the container names the package even when its value is garbage');
        self::assertSame('package value is not a list of advisories', $result['gaps'][0]->reason);
        self::assertSame('upstream-error', $result['gaps'][0]->raw);
        self::assertSame('acme/null', $result['gaps'][1]->package);

        $list = (new PackagistShapeMapper())->mapDocument(['advisories' => [['advisoryId' => 'X-1', 'affectedVersions' => '<1.0']]], 'Test');
        self::assertSame([], $list['records'], 'a list where the package map should be cannot attribute its entries');
        self::assertCount(1, $list['gaps']);
        self::assertNull($list['gaps'][0]->package);
        self::assertSame('advisories map has a non-string package key', $list['gaps'][0]->reason);
    }

    public function testPrivateAdvisoryFileWithAMalformedPackageContainerFailsTheBuild(): void
    {
        $file = $this->tmp('.json');
        file_put_contents($file, '{"advisories":{"acme/lib":"upstream-error"}}');
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('package value is not a list of advisories');
        (new JsonFileSource($file))->fetch(static function (): void {
        });
    }

    public function testPrivateAdvisoryFileWithAnUnreadableRecordFailsTheBuild(): void
    {
        $file = $this->tmp('.json');
        file_put_contents($file, json_encode(['advisories' => ['acme/lib' => [['advisoryId' => 'PRIV-1', 'affectedVersions' => 'garbage !!']]]]));
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('cannot be interpreted');
        (new JsonFileSource($file))->fetch(static function (): void {
        });
    }

    public function testGapsAreStoredAndSurfaceAsPlanWarningsForLockedPackages(): void
    {
        $db = $this->tmp('.sqlite');
        $good = new NormalizedAdvisory('CVE-2026-1', ['CVE-2026-1'], 't', null, 'high', null, null, [new AffectedRange('acme/other', '<9.0', 'Upstream')], [new SourceRecord('Upstream', 'CVE-2026-1')]);
        $gaps = [
            new CoverageGap('Upstream', 'GHSA-bad', 'acme/lib', 'unparsable affectedVersions', 'garbage !!'),
            new CoverageGap('Upstream', 'GHSA-elsewhere', 'someone/else', 'no usable range'),
        ];
        $result = (new DatabaseBuilder([$this->source([$good], $gaps)]))->build($db, static function (): void {
        });
        self::assertSame(2, $result['gaps']);

        $database = Database::open($db);
        self::assertTrue($database->tracksGaps());
        self::assertSame(2, $database->gapCount());
        self::assertSame('2', $database->meta()['gap_count']);
        self::assertCount(1, $database->gapsFor(['acme/lib']));
        self::assertCount(0, $database->gapsFor(['acme/other']));

        $project = new ScriptedProject(['acme/lib' => '^1.0'], [['acme/lib', '1.0.0']]);
        try {
            $plan = (new Planner(new SqliteAdvisoryProvider($database), new FakeSolver()))->plan($project->context(), $project->workspace());
        } finally {
            $project->destroy();
        }
        self::assertSame(Plan::EXIT_CLEAN, $plan->exitCode(), 'no advisory could be read for acme/lib, so nothing is found');
        self::assertCount(1, $plan->warnings, 'but the report says so');
        self::assertStringContainsString('Coverage gap: Upstream record GHSA-bad for acme/lib could not be interpreted', $plan->warnings[0]);
        self::assertStringContainsString('acme/lib is treated as unaffected', $plan->warnings[0]);
    }

    public function testDatabaseWithoutGapTableIsFlagged(): void
    {
        $db = $this->tmp('.sqlite');
        (new DatabaseBuilder([$this->source([], [])]))->build($db, static function (): void {
        });
        $pdo = new \PDO('sqlite:' . $db);
        $pdo->exec('DROP TABLE gap');
        $pdo = null;
        $database = Database::open($db);
        self::assertFalse($database->tracksGaps());
        $warnings = (new SqliteAdvisoryProvider($database))->coverageWarnings(['acme/lib']);
        self::assertCount(1, $warnings);
        self::assertStringContainsString('built before coverage gaps were recorded', $warnings[0]);
    }
}
