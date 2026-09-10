<?php

declare(strict_types=1);

namespace Remediate\Tests\Unit\Advisory\Enrichment;

use PHPUnit\Framework\TestCase;
use Remediate\Engine\Advisory\Db\Enrichment\EpssSource;
use Remediate\Tests\Support\ScriptedDownloader;

final class EpssSourceTest extends TestCase
{
    private const CSV = "#model_version:v2025.03.14,score_date:2026-09-09T00:00:00+0000\ncve,epss,percentile\nCVE-2026-00001,0.93412,0.99871\ncve-2021-44228,0.97,0.999\nnot-a-cve,0.5,0.5\nCVE-2020-0001,abc,0.1\nCVE-2019-0001,0.001,\n";

    private string $tempDir;

    protected function setUp(): void
    {
        $this->tempDir = sys_get_temp_dir() . '/composer-remediate-epss-' . bin2hex(random_bytes(4));
    }

    protected function tearDown(): void
    {
        foreach (glob($this->tempDir . '/*') ?: [] as $file) {
            @unlink($file);
        }
        @rmdir($this->tempDir);
    }

    public function testReadsTheGzippedFeedAndItsHeaderComment(): void
    {
        $downloader = new ScriptedDownloader([EpssSource::URL => (string) gzencode(self::CSV)]);
        $source = new EpssSource($downloader, $this->tempDir);
        $log = [];
        $result = $source->fetch(static function (string $line) use (&$log): void {
            $log[] = $line;
        });

        self::assertSame('EPSS', $source->name());
        self::assertSame([EpssSource::URL], $downloader->requested());
        self::assertSame(['CVE-2026-00001', 'CVE-2021-44228', 'CVE-2019-0001'], array_keys($result['records']), 'ids are upper-cased; non-CVE and non-numeric rows are skipped');
        self::assertSame(0.93412, $result['records']['CVE-2026-00001']->epss);
        self::assertSame(0.99871, $result['records']['CVE-2026-00001']->epssPercentile);
        self::assertNull($result['records']['CVE-2019-0001']->epssPercentile, 'an empty percentile is unknown, not zero');
        self::assertNull($result['records']['CVE-2026-00001']->kevAdded, 'EPSS says nothing about KEV');
        self::assertSame(['epss_model_version' => 'v2025.03.14', 'epss_score_date' => '2026-09-09T00:00:00+0000', 'epss_count' => '3'], $result['meta']);
        self::assertSame(['EPSS: downloading the current scores…', 'EPSS: 3 scored CVEs, scored 2026-09-09T00:00:00+0000'], $log);
        self::assertSame([], glob($this->tempDir . '/*') ?: [], 'the download is removed');
    }

    public function testReadsAPlainLocalCopy(): void
    {
        $file = tempnam(sys_get_temp_dir(), 'epss');
        self::assertNotFalse($file);
        file_put_contents($file, self::CSV);
        try {
            $downloader = new ScriptedDownloader([]);
            $result = (new EpssSource($downloader, $this->tempDir, $file))->fetch(static function (): void {});
            self::assertCount(3, $result['records']);
            self::assertSame([], $downloader->requested(), 'nothing is downloaded when a local file is given');
        } finally {
            unlink($file);
        }
    }

    public function testAFeedWithoutTheExpectedColumnsIsAnError(): void
    {
        $source = new EpssSource(new ScriptedDownloader([EpssSource::URL => "id,score\nCVE-2026-1,0.5\n"]), $this->tempDir);
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('EPSS feed has no cve/epss columns');
        $source->fetch(static function (): void {});
    }

    public function testAnEmptyFeedIsAnError(): void
    {
        $source = new EpssSource(new ScriptedDownloader([EpssSource::URL => "#model_version:x\n"]), $this->tempDir);
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('EPSS feed is empty');
        $source->fetch(static function (): void {});
    }
}
