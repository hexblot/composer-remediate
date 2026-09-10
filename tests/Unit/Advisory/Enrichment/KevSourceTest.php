<?php

declare(strict_types=1);

namespace Remediate\Tests\Unit\Advisory\Enrichment;

use PHPUnit\Framework\TestCase;
use Remediate\Engine\Advisory\Db\Enrichment\KevSource;
use Remediate\Tests\Support\ScriptedDownloader;

final class KevSourceTest extends TestCase
{
    /** @return array<string, mixed> */
    private static function catalogue(): array
    {
        return [
            'title' => 'CISA Catalog of Known Exploited Vulnerabilities',
            'catalogVersion' => '2026.09.09',
            'dateReleased' => '2026-09-09T14:00:00.0000Z',
            'count' => 3,
            'vulnerabilities' => [
                ['cveID' => 'CVE-2026-00001', 'vendorProject' => 'Acme', 'product' => 'vuln-lib', 'dateAdded' => '2026-02-01', 'knownRansomwareCampaignUse' => 'Known'],
                ['cveID' => 'cve-2021-44228', 'dateAdded' => '2021-12-10', 'knownRansomwareCampaignUse' => 'Unknown'],
                ['cveID' => 'CVE-2020-0001', 'dateAdded' => 'not a date'],
                ['cveID' => 'GHSA-not-a-cve', 'dateAdded' => '2026-01-01'],
                'not an entry',
            ],
        ];
    }

    public function testReadsTheCatalogue(): void
    {
        $downloader = new ScriptedDownloader([KevSource::URL => json_encode(self::catalogue(), JSON_THROW_ON_ERROR)]);
        $source = new KevSource($downloader);
        $log = [];
        $result = $source->fetch(static function (string $line) use (&$log): void {
            $log[] = $line;
        });

        self::assertSame('KEV', $source->name());
        self::assertSame([KevSource::URL], $downloader->requested());
        self::assertSame(['CVE-2026-00001', 'CVE-2021-44228', 'CVE-2020-0001'], array_keys($result['records']));
        self::assertSame('2026-02-01', $result['records']['CVE-2026-00001']->kevAdded?->format('Y-m-d'));
        self::assertTrue($result['records']['CVE-2026-00001']->kevRansomware);
        self::assertFalse($result['records']['CVE-2021-44228']->kevRansomware);
        self::assertNull($result['records']['CVE-2026-00001']->epss, 'KEV says nothing about EPSS');
        self::assertSame('1970-01-01', $result['records']['CVE-2020-0001']->kevAdded?->format('Y-m-d'), 'an unreadable date still marks the CVE as listed');
        self::assertSame(['kev_count' => '3', 'kev_catalog_version' => '2026.09.09', 'kev_date_released' => '2026-09-09T14:00:00.0000Z'], $result['meta']);
        self::assertSame(['KEV: downloading the CISA catalogue…', 'KEV: 3 known exploited CVEs, catalogue released 2026-09-09T14:00:00.0000Z'], $log);
    }

    public function testReadsALocalCopy(): void
    {
        $file = tempnam(sys_get_temp_dir(), 'kev');
        self::assertNotFalse($file);
        file_put_contents($file, json_encode(self::catalogue(), JSON_THROW_ON_ERROR));
        try {
            $downloader = new ScriptedDownloader([]);
            $result = (new KevSource($downloader, $file))->fetch(static function (): void {});
            self::assertCount(3, $result['records']);
            self::assertSame([], $downloader->requested());
        } finally {
            unlink($file);
        }
    }

    public function testADocumentWithoutVulnerabilitiesIsAnError(): void
    {
        $source = new KevSource(new ScriptedDownloader([KevSource::URL => '{"title": "x"}']));
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('KEV catalogue has no "vulnerabilities" list');
        $source->fetch(static function (): void {});
    }
}
