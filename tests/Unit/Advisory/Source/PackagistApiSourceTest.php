<?php

declare(strict_types=1);

namespace Remediate\Tests\Unit\Advisory\Source;

use Composer\Downloader\TransportException;
use PHPUnit\Framework\TestCase;
use Remediate\Engine\Advisory\Db\Source\PackagistApiSource;
use Remediate\Tests\Support\ScriptedDownloader;

final class PackagistApiSourceTest extends TestCase
{
    public function testMapsTheDumpAndReportsUnreadableRecordsAsGaps(): void
    {
        $document = ['advisories' => ['Acme/Lib' => [
            [
                'advisoryId' => 'PKSA-1',
                'affectedVersions' => '>=1.0,<1.0.5|>=2.0,<2.0.1',
                'cve' => 'CVE-2026-20001',
                'title' => 'Synthetic advisory',
                'link' => 'https://example.invalid/pksa-1',
                'severity' => 'High',
                'reportedAt' => '2026-01-20 10:00:00',
                'sources' => [['name' => 'GitHub', 'remoteId' => 'GHSA-zzzz']],
            ],
            ['advisoryId' => 'PKSA-2', 'affectedVersions' => 'nonsense !!'],
        ]]];
        $downloader = new ScriptedDownloader([PackagistApiSource::URL => json_encode($document, JSON_THROW_ON_ERROR)]);
        $source = new PackagistApiSource($downloader);
        $log = [];
        $records = $source->fetch(static function (string $line) use (&$log): void {
            $log[] = $line;
        });

        self::assertSame('Packagist', $source->name());
        self::assertSame([PackagistApiSource::URL], $downloader->requested());
        self::assertSame(['Packagist: downloading the advisory dump…', 'Packagist: 1 records, 1 skipped (recorded as coverage gaps)'], $log);

        self::assertCount(1, $records);
        $record = $records[0];
        self::assertSame('CVE-2026-20001', $record->canonicalId);
        self::assertSame(['CVE-2026-20001', 'GHSA-zzzz', 'PKSA-1'], $record->aliases);
        self::assertSame('Synthetic advisory', $record->title);
        self::assertSame('https://example.invalid/pksa-1', $record->link);
        self::assertSame('high', $record->severity);
        self::assertSame('2026-01-20T10:00:00+00:00', $record->reportedAt?->format(DATE_ATOM));
        self::assertSame(['acme/lib'], $record->packages());
        self::assertSame('>=1.0,<1.0.5|>=2.0,<2.0.1', $record->affected[0]->constraint);
        self::assertSame('Packagist', $record->affected[0]->source);
        self::assertSame(['Packagist', 'GitHub'], array_map(static fn ($s): string => $s->name, $record->sources));

        $gaps = $source->gaps();
        self::assertCount(1, $gaps);
        self::assertSame('PKSA-2', $gaps[0]->remoteId);
        self::assertSame('acme/lib', $gaps[0]->package);
        self::assertSame('unparsable affectedVersions', $gaps[0]->reason);
        self::assertSame('nonsense !!', $gaps[0]->raw);
    }

    public function testABodyThatIsNotAnObjectIsAnError(): void
    {
        $source = new PackagistApiSource(new ScriptedDownloader([PackagistApiSource::URL => '"just a string"']));
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Packagist advisory dump is not a JSON object');
        $source->fetch(static function (): void {});
    }

    public function testAnObjectWithoutAdvisoriesIsAnError(): void
    {
        $source = new PackagistApiSource(new ScriptedDownloader([PackagistApiSource::URL => '{"packages": {}}']));
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Packagist: document has no "advisories" map');
        $source->fetch(static function (): void {});
    }

    public function testADownloadFailurePropagatesAndACustomUrlIsHonoured(): void
    {
        $url = 'https://mirror.test/security-advisories';
        $downloader = new ScriptedDownloader([$url => 500]);
        $source = new PackagistApiSource($downloader, url: $url);
        try {
            $source->fetch(static function (): void {});
            self::fail('expected the transport failure to propagate');
        } catch (TransportException $e) {
            self::assertSame(500, $e->getCode());
        }
        self::assertSame([$url], $downloader->requested());
    }
}
