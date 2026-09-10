<?php

declare(strict_types=1);

namespace Remediate\Tests\Unit\Advisory\Source;

use Composer\Downloader\TransportException;
use PHPUnit\Framework\TestCase;
use Remediate\Engine\Advisory\Db\Source\ZipArchiveReader;
use Remediate\Tests\Support\ScriptedDownloader;
use Remediate\Tests\Support\Zips;

final class ZipArchiveReaderTest extends TestCase
{
    private const URL = 'https://example.test/archive.zip';

    private string $tempDir;

    protected function setUp(): void
    {
        $this->tempDir = sys_get_temp_dir() . '/composer-remediate-zip-' . bin2hex(random_bytes(4));
    }

    protected function tearDown(): void
    {
        foreach (glob($this->tempDir . '/*') ?: [] as $file) {
            @unlink($file);
        }
        @rmdir($this->tempDir);
    }

    public function testVisitsTheFilteredFilesOnceAndRemovesTheDownload(): void
    {
        $zip = Zips::build([
            'top/a.json' => 'A',
            'top/b.txt' => 'B',
            'top/sub/' => '',
            'top/sub/c.json' => 'C',
        ]);
        $downloader = new ScriptedDownloader([self::URL => $zip]);
        $seen = [];
        $count = (new ZipArchiveReader($downloader, $this->tempDir))->each(
            self::URL,
            static fn (string $name): bool => str_ends_with($name, '.json'),
            static function (string $name, string $contents) use (&$seen): void {
                $seen[$name] = $contents;
            },
        );

        self::assertSame(2, $count);
        self::assertSame(['top/a.json' => 'A', 'top/sub/c.json' => 'C'], $seen);
        self::assertSame([self::URL], $downloader->requested());
        self::assertSame([], glob($this->tempDir . '/*.zip') ?: [], 'the downloaded archive is deleted after reading');
    }

    public function testABodyThatIsNotAnArchiveIsAnErrorAndLeavesNoFile(): void
    {
        $downloader = new ScriptedDownloader([self::URL => 'this is not a zip file']);
        try {
            (new ZipArchiveReader($downloader, $this->tempDir))->each(self::URL, static fn (): bool => true, static function (): void {});
            self::fail('expected the reader to reject the body');
        } catch (\RuntimeException $e) {
            self::assertStringContainsString('Cannot open archive from ' . self::URL, $e->getMessage());
        }
        self::assertSame([], glob($this->tempDir . '/*.zip') ?: []);
    }

    public function testADownloadFailurePropagates(): void
    {
        $downloader = new ScriptedDownloader([]);
        $this->expectException(TransportException::class);
        (new ZipArchiveReader($downloader, $this->tempDir))->each(self::URL, static fn (): bool => true, static function (): void {});
    }
}
