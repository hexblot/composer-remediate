<?php

declare(strict_types=1);

namespace Remediate\Tests\Support;

/**
 * Builds small zip archives in memory for the feed-reader tests.
 */
final class Zips
{
    /**
     * @param array<string, string> $entries entry name => contents; a name ending in "/" adds an empty directory
     *
     * @return string the archive bytes
     */
    public static function build(array $entries): string
    {
        if ($entries === []) {
            // ZipArchive writes no file for an archive without entries; this is the canonical empty archive.
            return "PK\x05\x06" . str_repeat("\0", 18);
        }
        $path = tempnam(sys_get_temp_dir(), 'composer-remediate-zip-');
        if ($path === false) {
            throw new \RuntimeException('Cannot create a temporary file for the archive');
        }
        $zip = new \ZipArchive();
        if ($zip->open($path, \ZipArchive::OVERWRITE) !== true) {
            throw new \RuntimeException("Cannot create archive $path");
        }
        foreach ($entries as $name => $contents) {
            if (str_ends_with($name, '/')) {
                $zip->addEmptyDir(rtrim($name, '/'));
            } else {
                $zip->addFromString($name, $contents);
            }
        }
        $zip->close();
        $bytes = (string) file_get_contents($path);
        unlink($path);

        return $bytes;
    }
}
