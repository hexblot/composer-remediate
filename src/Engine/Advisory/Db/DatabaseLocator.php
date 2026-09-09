<?php

declare(strict_types=1);

namespace Remediate\Engine\Advisory\Db;

use Composer\Composer;
use Composer\Downloader\TransportException;
use Composer\Util\HttpDownloader;
use Remediate\Engine\Advisory\AdvisoryLookupFailed;

/**
 * Resolves where the advisory database comes from: the --database-location option, the
 * REMEDIATE_DATABASE environment variable, or extra.remediate.database in composer.json. A URL is
 * downloaded once into Composer's cache directory and refreshed when older than the TTL.
 */
final class DatabaseLocator
{
    public const ENV = 'REMEDIATE_DATABASE';
    public const TTL_SECONDS = 24 * 3600;

    public function __construct(private readonly Composer $composer, private readonly HttpDownloader $downloader, private readonly bool $offline = false)
    {
    }

    /** Where `db:build` writes by default and where a URL download is cached. */
    public function cacheDirectory(): string
    {
        $dir = $this->composer->getConfig()->get('cache-dir');

        return rtrim(is_string($dir) && $dir !== '' ? $dir : sys_get_temp_dir(), '/') . '/remediate';
    }

    public function defaultBuildPath(): string
    {
        return $this->cacheDirectory() . '/advisories.sqlite';
    }

    /** The configured location, or null when none is configured. */
    public function configured(?string $option): ?string
    {
        if ($option !== null && $option !== '') {
            return $option;
        }
        $env = getenv(self::ENV);
        if (is_string($env) && $env !== '') {
            return $env;
        }
        $extra = $this->composer->getPackage()->getExtra();
        if (isset($extra['remediate']) && is_array($extra['remediate']) && is_string($extra['remediate']['database'] ?? null) && $extra['remediate']['database'] !== '') {
            return $extra['remediate']['database'];
        }

        return null;
    }

    /**
     * Turns a location into a local file path, downloading URLs when needed.
     *
     * @throws AdvisoryLookupFailed
     */
    public function resolve(string $location): string
    {
        if (preg_match('{^https?://}i', $location) === 1) {
            return $this->download($location);
        }
        $path = $location;
        if (!str_starts_with($path, '/') && !preg_match('{^[A-Za-z]:[\\\\/]}', $path)) {
            $path = getcwd() . '/' . $path;
        }
        $real = realpath($path);
        if ($real === false) {
            throw new AdvisoryLookupFailed(sprintf('Advisory database %s does not exist.', $location));
        }

        return $real;
    }

    private function download(string $url): string
    {
        $dir = $this->cacheDirectory();
        @mkdir($dir, 0755, true);
        $file = $dir . '/db-' . sha1($url) . '.sqlite';
        $fresh = is_file($file) && (time() - (int) filemtime($file)) < self::TTL_SECONDS;
        if ($fresh || ($this->offline && is_file($file))) {
            return $file;
        }
        if ($this->offline) {
            throw new AdvisoryLookupFailed(sprintf('Offline mode and no cached copy of %s.', $url));
        }
        $tmp = $file . '.tmp-' . bin2hex(random_bytes(4));
        try {
            $this->downloader->copy($url, $tmp);
        } catch (TransportException $e) {
            @unlink($tmp);
            if (is_file($file)) {
                return $file; // stale but usable
            }
            throw new AdvisoryLookupFailed(sprintf('Could not download advisory database %s: %s', $url, $e->getMessage()), 0, $e);
        }
        if (!@rename($tmp, $file)) {
            @unlink($tmp);
            throw new AdvisoryLookupFailed(sprintf('Could not store downloaded advisory database in %s.', $file));
        }

        return $file;
    }
}
