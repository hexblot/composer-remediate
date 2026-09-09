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
 *
 * Downloads are checked against the publisher's `<url>.sha256` sidecar when one exists; a mismatch
 * is fatal. When a refresh fails and an older cached copy is used instead, that is reported through
 * warnings() so a report never presents stale coverage as current.
 */
final class DatabaseLocator
{
    public const ENV = 'REMEDIATE_DATABASE';
    public const TTL_SECONDS = 24 * 3600;

    /** @var list<string> */
    private array $warnings = [];

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

    /**
     * Conditions under which the resolved database is weaker than it looks (stale cache after a failed
     * refresh, download without a checksum), to be shown with the report.
     *
     * @return list<string>
     */
    public function warnings(): array
    {
        return $this->warnings;
    }

    private function download(string $url): string
    {
        $dir = $this->cacheDirectory();
        @mkdir($dir, 0755, true);
        $file = $dir . '/db-' . sha1($url) . '.sqlite';
        $fresh = is_file($file) && (time() - (int) filemtime($file)) < self::TTL_SECONDS;
        if ($fresh) {
            $this->recallVerification($file, $url);

            return $file;
        }
        if ($this->offline) {
            if (is_file($file)) {
                $this->warnings[] = sprintf('Offline: using the advisory database cached %s from %s; advisories published since then are unknown.', self::age($file), $url);
                $this->recallVerification($file, $url);

                return $file;
            }
            throw new AdvisoryLookupFailed(sprintf('Offline mode and no cached copy of %s.', $url));
        }
        $tmp = $file . '.tmp-' . bin2hex(random_bytes(4));
        try {
            $this->downloader->copy($url, $tmp);
        } catch (TransportException $e) {
            @unlink($tmp);
            if (is_file($file)) {
                $this->warnings[] = sprintf('Advisory database refresh failed (%s); using the copy cached %s. Advisories published since then are unknown to this run.', self::shortError($e), self::age($file));
                $this->recallVerification($file, $url);

                return $file;
            }
            throw new AdvisoryLookupFailed(sprintf('Could not download advisory database %s: %s', $url, $e->getMessage()), 0, $e);
        }
        $verified = $this->verifyChecksum($url, $tmp);
        if (!@rename($tmp, $file)) {
            @unlink($tmp);
            throw new AdvisoryLookupFailed(sprintf('Could not store downloaded advisory database in %s.', $file));
        }
        // The verification outcome is a property of the cached bytes, not of this request: record it so
        // every later run that reuses the cache repeats the disclosure.
        @file_put_contents(self::statusFile($file), json_encode(['verified' => $verified, 'url' => $url, 'fetched_at' => gmdate(DATE_ATOM)], JSON_THROW_ON_ERROR));

        return $file;
    }

    private static function statusFile(string $file): string
    {
        return $file . '.status.json';
    }

    /** Re-emits the disclosure recorded when the cached copy was downloaded. */
    private function recallVerification(string $file, string $url): void
    {
        $raw = @file_get_contents(self::statusFile($file));
        $status = is_string($raw) ? json_decode($raw, true) : null;
        if (!is_array($status) || !array_key_exists('verified', $status)) {
            $this->warnings[] = sprintf('The cached copy of %s carries no verification record (downloaded by an older version); its sha256 was not checked against the publisher\'s.', $url);

            return;
        }
        if ($status['verified'] !== true) {
            $this->warnings[] = sprintf('The cached copy of %s was downloaded without a published sha256 to verify against (%s).', $url, is_string($status['fetched_at'] ?? null) ? 'fetched ' . $status['fetched_at'] : 'date unknown');
        }
    }

    /**
     * Compares the download with the publisher's `<url>.sha256` sidecar (either a bare digest or
     * `sha256sum` output with a filename). No sidecar means no verification, which is reported.
     * Returns whether the download was verified.
     */
    private function verifyChecksum(string $url, string $file): bool
    {
        $sidecar = $file . '.sha256';
        try {
            $this->downloader->copy($url . '.sha256', $sidecar);
        } catch (TransportException $e) {
            @unlink($sidecar);
            $this->warnings[] = sprintf('No checksum published next to %s (%s); the download was not verified against a sha256.', $url, self::shortError($e));

            return false;
        }
        $published = trim((string) file_get_contents($sidecar));
        @unlink($sidecar);
        if (preg_match('{^([0-9a-f]{64})\b}i', $published, $m) !== 1) {
            @unlink($file);
            throw new AdvisoryLookupFailed(sprintf('The checksum file at %s.sha256 is not a sha256 digest.', $url));
        }
        $actual = hash_file('sha256', $file);
        if ($actual === false || !hash_equals(strtolower($m[1]), $actual)) {
            @unlink($file);
            throw new AdvisoryLookupFailed(sprintf('Advisory database %s does not match its published sha256 (expected %s, got %s).', $url, $m[1], $actual === false ? '?' : $actual));
        }

        return true;
    }

    private static function age(string $file): string
    {
        $seconds = max(0, time() - (int) filemtime($file));
        if ($seconds < 3600 * 48) {
            return sprintf('%d hour%s ago', intdiv($seconds, 3600), intdiv($seconds, 3600) === 1 ? '' : 's');
        }

        return sprintf('%d days ago', intdiv($seconds, 86400));
    }

    private static function shortError(\Throwable $e): string
    {
        $code = $e->getCode();

        return $code !== 0 ? sprintf('HTTP %d', $code) : trim(explode("\n", $e->getMessage())[0]);
    }
}
