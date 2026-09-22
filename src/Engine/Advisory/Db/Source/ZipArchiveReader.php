<?php

declare(strict_types=1);

namespace Remediate\Engine\Advisory\Db\Source;

use Composer\Util\HttpDownloader;
use Remediate\Engine\Advisory\Db\Download;

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
     * @param callable(string): bool                              $filter       entry names to read
     * @param (callable(string $entryName): void)|null            $onUnreadable what to do with an entry that matched the
     *                                                                          filter but whose bytes could not be read.
     *                                                                          Null refuses the whole archive, which is the
     *                                                                          right default: an entry that cannot be read
     *                                                                          is not an entry that is not there, and a
     *                                                                          caller with nowhere to record that must not
     *                                                                          receive a short archive as a complete one.
     */
    public function each(string $url, callable $filter, callable $visit, ?callable $onUnreadable = null): int
    {
        if (!class_exists(\ZipArchive::class)) {
            throw new \RuntimeException('The zip PHP extension is required to read ' . $url);
        }
        @mkdir($this->tempDir, 0700, true);
        $file = $this->tempDir . '/' . sha1($url) . '.zip';
        Download::toFile($this->downloader, $url, $file);
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
                    // Encrypted, corrupt or truncated. Skipping it silently made a partial archive
                    // indistinguishable from a complete one: the source counted the entries it could
                    // read, reported no gaps, and every advisory in the unreadable members disappeared
                    // from coverage without anything saying so.
                    if ($onUnreadable === null) {
                        throw new \RuntimeException(sprintf('Entry %s of the archive from %s could not be read', $name, $url));
                    }
                    $onUnreadable($name);
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
