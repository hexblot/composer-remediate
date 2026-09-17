<?php

declare(strict_types=1);

namespace Remediate\Tests\Unit\Output;

use JsonSchema\Validator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

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

    public function testTheVersionedSchemaMatchesTheCurrentOne(): void
    {
        // report.schema.json describes whatever the tool emits today; report-v1.schema.json describes
        // schema_version 1 for good, and is the one a consumer is told to pin. While the tool emits
        // version 1 they must say the same thing apart from their own identity, or a consumer that
        // followed the advice would be validating against something the tool no longer produces.
        $current = json_decode((string) file_get_contents(__DIR__ . '/../../../docs/schema/report.schema.json'), true, 512, JSON_THROW_ON_ERROR);
        $versioned = json_decode((string) file_get_contents(__DIR__ . '/../../../docs/schema/report-v1.schema.json'), true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($current);
        self::assertIsArray($versioned);
        self::assertSame('https://hexblot.github.io/composer-remediate/schema/report-v1.schema.json', $versioned['$id']);
        unset($current['$id'], $versioned['$id']);
        self::assertSame($current, $versioned);
        self::assertSame(1, $current['properties']['schema_version']['const'] ?? null, 'when this stops being 1, report-v1 stops tracking report and must be frozen');
    }
}
