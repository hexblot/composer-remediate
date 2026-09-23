<?php

declare(strict_types=1);

namespace Remediate\Tests\Unit\Output;

use JsonSchema\Validator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Remediate\Output\JsonRenderer;

/**
 * Every stored fixture report must validate against the published schema. Freshly rendered reports
 * are validated in FixtureTest; this guards the committed examples.
 */
final class JsonSchemaTest extends TestCase
{
    /** @return iterable<string, array{string}> */
    public static function reports(): iterable
    {
        foreach (glob(__DIR__ . '/../../Fixture/third-party/*/reports/report.json') ?: [] as $file) {
            yield basename(dirname($file, 2)) => [$file];
        }
    }

    #[DataProvider('reports')]
    public function testStoredReportMatchesSchema(string $file): void
    {
        $schemaPath = realpath(__DIR__ . '/../../../docs/schema/report.schema.json');
        self::assertNotFalse($schemaPath);
        $data = json_decode((string) file_get_contents($file));
        $validator = new Validator();
        $validator->validate($data, (object) ['$ref' => 'file://' . $schemaPath]);
        $errors = array_map(static fn (array $e): string => sprintf('%s: %s', $e['property'], $e['message']), $validator->getErrors());
        self::assertTrue($validator->isValid(), "Schema violations in $file:\n" . implode("\n", $errors));
    }

    public function testTheCurrentSchemaMatchesThePinnableCopyOfTheVersionItEmits(): void
    {
        // report.schema.json describes whatever the tool emits today; report-v<N>.schema.json describes
        // schema_version N for good, and is the one a consumer is told to pin. They must say the same
        // thing apart from their own identity, or a consumer that followed the advice would be
        // validating against something the tool no longer produces.
        $version = JsonRenderer::SCHEMA_VERSION;
        $current = self::schema('report.schema.json');
        $pinned = self::schema(sprintf('report-v%d.schema.json', $version));

        self::assertSame(sprintf('https://hexblot.github.io/composer-remediate/schema/report-v%d.schema.json', $version), $pinned['$id']);
        self::assertSame($version, $current['properties']['schema_version']['const'] ?? null);
        unset($current['$id'], $pinned['$id']);
        self::assertSame($current, $pinned);
    }

    /**
     * Every earlier version's schema stays exactly what it was. A pin is worth nothing if the file it
     * names moves, so these are frozen once the tool stops emitting that version, and the test says so
     * rather than leaving it to whoever edits the schema next.
     */
    public function testEveryEarlierSchemaIsFrozenAtItsOwnVersion(): void
    {
        $current = JsonRenderer::SCHEMA_VERSION;
        self::assertGreaterThan(1, $current, 'this test means nothing until a second version exists');

        for ($version = 1; $version < $current; ++$version) {
            $file = sprintf('report-v%d.schema.json', $version);
            $schema = self::schema($file);
            self::assertSame($version, $schema['properties']['schema_version']['const'] ?? null, $file . ' no longer describes the version it is named for');
            self::assertNotSame(
                self::schema('report.schema.json')['definitions'] ?? null,
                $schema['definitions'] ?? null,
                $file . ' has drifted into describing the current report; a consumer pinning it would validate against something the tool no longer emits',
            );
        }
    }

    /** @return array<string, mixed> */
    private static function schema(string $file): array
    {
        $decoded = json_decode((string) file_get_contents(__DIR__ . '/../../../docs/schema/' . $file), true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($decoded, $file . ' is not readable as JSON');

        return $decoded;
    }
}
