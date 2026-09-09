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
        foreach (glob(__DIR__ . '/../../Fixture/*/reports/report.json') ?: [] as $file) {
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
}
