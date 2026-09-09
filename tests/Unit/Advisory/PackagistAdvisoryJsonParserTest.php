<?php

declare(strict_types=1);

namespace Remediate\Tests\Unit\Advisory;

use PHPUnit\Framework\TestCase;
use Remediate\Engine\Advisory\AdvisoryLookupFailed;
use Remediate\Engine\Advisory\JsonFileAdvisoryProvider;
use Remediate\Engine\Advisory\PackagistAdvisoryJsonParser;

final class PackagistAdvisoryJsonParserTest extends TestCase
{
    /** @var list<string> */
    private array $files = [];

    protected function tearDown(): void
    {
        foreach ($this->files as $file) {
            @unlink($file);
        }
    }

    private function file(string $json): string
    {
        $path = tempnam(sys_get_temp_dir(), 'adv');
        self::assertNotFalse($path);
        file_put_contents($path, $json);

        return $this->files[] = $path;
    }

    public function testErrorPayloadIsNotAnEmptyResult(): void
    {
        $this->expectException(AdvisoryLookupFailed::class);
        $this->expectExceptionMessage('upstream unavailable');
        (new PackagistAdvisoryJsonParser())->parseDocument(['error' => 'upstream unavailable']);
    }

    public function testMalformedEntryFails(): void
    {
        $this->expectException(AdvisoryLookupFailed::class);
        (new PackagistAdvisoryJsonParser())->parseDocument(['advisories' => ['acme/lib' => ['not-an-object']]]);
    }

    public function testUnparsableRangeFailsInsteadOfMatchingNothing(): void
    {
        $this->expectException(AdvisoryLookupFailed::class);
        $this->expectExceptionMessage('unparsable affectedVersions');
        (new PackagistAdvisoryJsonParser())->parseRecord('acme/lib', ['advisoryId' => 'PKSA-1', 'affectedVersions' => 'garbage !!']);
    }

    public function testValidRecordParses(): void
    {
        $advisory = (new PackagistAdvisoryJsonParser())->parseRecord('Acme/Lib', ['advisoryId' => 'PKSA-1', 'affectedVersions' => '<1.0.0', 'severity' => 'high', 'cve' => 'CVE-2026-1']);
        self::assertSame('acme/lib', $advisory->packageName);
        self::assertTrue($advisory->affectsVersion('0.9.0.0'));
        self::assertFalse($advisory->affectsVersion('1.0.0.0'));
    }

    public function testAuditOutputIsRecognisedAsIncomplete(): void
    {
        $audit = new JsonFileAdvisoryProvider($this->file('{"advisories": {"acme/lib": []}, "abandoned": []}'));
        self::assertFalse($audit->isComplete());
        self::assertStringContainsString('current-lock advisories only', $audit->describe());

        $dump = new JsonFileAdvisoryProvider($this->file('{"advisories": {"acme/lib": []}}'));
        self::assertTrue($dump->isComplete());

        $forced = new JsonFileAdvisoryProvider($this->file('{"advisories": {}}'), new PackagistAdvisoryJsonParser(), false);
        self::assertFalse($forced->isComplete());
    }

    public function testInvalidFileFails(): void
    {
        $this->expectException(AdvisoryLookupFailed::class);
        (new JsonFileAdvisoryProvider($this->file('{"error": "nope"}')))->advisoriesFor(['acme/lib']);
    }
}
