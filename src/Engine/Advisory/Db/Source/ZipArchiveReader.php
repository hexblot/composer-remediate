<?php

declare(strict_types=1);

namespace Remediate\Engine\Advisory\Db\Source;

use Composer\Util\HttpDownloader;

/**
 * Downloads a zip archive to a temporary file and iterates its entries.
 */
final class ZipArchiveReader
{
    public function __construct(private readonly HttpDownloader $downloader, private readonly string $tempDir)
    {
    }

    /**
     * @param callable(string $entryName, string $contents): void $visit
     * @param callable(string): bool $filter entry names to read
     */
    public function each(string $url, callable $filter, callable $visit): int
    {
        if (!class_exists(\ZipArchive::class)) {
            throw new \RuntimeException('The zip PHP extension is required to read ' . $url);
        }
        @mkdir($this->tempDir, 0700, true);
        $file = $this->tempDir . '/' . sha1($url) . '.zip';
        $this->downloader->copy($url, $file);
        $zip = new \ZipArchive();
        $status = $zip->open($file);
        if ($status !== true) {
            @unlink($file);
            throw new \RuntimeException(sprintf('Cannot open archive from %s (ZipArchive error %s)', $url, var_export($status, true)));
        }
        $count = 0;
        try {
            for ($i = 0; $i < $zip->numFiles; ++$i) {
                $name = $zip->getNameIndex($i);
                if ($name === false || str_ends_with($name, '/') || !$filter($name)) {
                    continue;
                }
                $contents = $zip->getFromIndex($i);
                if ($contents === false) {
                    continue;
                }
                $visit($name, $contents);
                ++$count;
            }
        } finally {
            $zip->close();
            @unlink($file);
        }

        return $count;
    }
}
