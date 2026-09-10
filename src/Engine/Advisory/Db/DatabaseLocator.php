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

    /**
     * @param bool        $requireChecksum refuse a URL download that no published `<url>.sha256` sidecar or expected
     *                                     digest verifies (the default); false accepts it with a warning in the report
     * @param string|null $expectedSha256  the digest the operator trusts (hex); a download or cached copy that differs
     *                                     is refused. The sidecar is only as trustworthy as the host that serves both,
     *                                     so this is the real trust anchor for a URL you do not publish yourself
     */
    public function __construct(
        private readonly Composer $composer,
        private readonly HttpDownloader $downloader,
        private readonly bool $offline = false,
        private readonly bool $requireChecksum = true,
        private readonly ?string $expectedSha256 = null,
    ) {
    }

    /** Text with the user:password part of every URL in it removed, for messages and stored metadata. */
    public static function redact(string $text): string
    {
        return preg_replace('{([a-z][a-z0-9+.-]*://)[^/?#@\s"\']*@}i', '$1***@', $text) ?? $text;
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
        if (preg_match('{^https://}i', $location) === 1) {
            return $this->download($location);
        }
        if (preg_match('{^[a-z][a-z0-9+.-]*://}i', $location) === 1) {
            // Advisory data decides a security gate: only TLS-protected downloads are accepted. This also
            // keeps a composer.json-configured location from pointing the tool at an internal http service.
            throw new AdvisoryLookupFailed(sprintf('Advisory database location %s is not an https URL or a local path; only https:// URLs are downloaded.', self::redact($location)));
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
        $shown = self::redact($url);
        $dir = $this->cacheDirectory();
        @mkdir($dir, 0700, true);
        $file = $dir . '/db-' . sha1($url) . '.sqlite';
        // The cache directory may be shared (Composer's cache under a shared HOME, or the temp dir as
        // a last resort). A symlink planted at one of the predictable names would make this process
        // write through it into a file of the attacker's choosing, so every path is checked first.
        foreach ([$dir, $file, self::statusFile($file)] as $path) {
            if (is_link($path)) {
                throw new AdvisoryLookupFailed(sprintf('Refusing to use the advisory database cache: %s is a symbolic link.', $path));
            }
        }
        $fresh = is_file($file) && (time() - (int) filemtime($file)) < self::TTL_SECONDS;
        if ($fresh) {
            $this->requireExpectedDigest($file, $shown);
            $this->recallVerification($file, $shown);

            return $file;
        }
        if ($this->offline) {
            if (is_file($file)) {
                $this->requireExpectedDigest($file, $shown);
                $this->warnings[] = sprintf('Offline: using the advisory database cached %s from %s; advisories published since then are unknown.', self::age($file), $shown);
                $this->recallVerification($file, $shown);

                return $file;
            }
            throw new AdvisoryLookupFailed(sprintf('Offline mode and no cached copy of %s.', $shown));
        }
        $tmp = $file . '.tmp-' . bin2hex(random_bytes(8));
        try {
            $this->downloader->copy($url, $tmp);
        } catch (TransportException $e) {
            @unlink($tmp);
            if (is_file($file)) {
                $this->requireExpectedDigest($file, $shown);
                $this->warnings[] = sprintf('Advisory database refresh failed (%s); using the copy cached %s. Advisories published since then are unknown to this run.', self::shortError($e), self::age($file));
                $this->recallVerification($file, $shown);

                return $file;
            }
            throw new AdvisoryLookupFailed(sprintf('Could not download advisory database %s: %s', $shown, self::redact($e->getMessage())), 0, $e);
        }
        $verified = $this->verifyChecksum($url, $tmp);
        if (!@rename($tmp, $file)) {
            @unlink($tmp);
            throw new AdvisoryLookupFailed(sprintf('Could not store downloaded advisory database in %s.', $file));
        }
        // The verification outcome is a property of the cached bytes, not of this request: record it so
        // every later run that reuses the cache repeats the disclosure. Written atomically, never through
        // an existing link (checked above), and without the URL's credentials.
        $statusTmp = self::statusFile($file) . '.tmp-' . bin2hex(random_bytes(8));
        if (@file_put_contents($statusTmp, json_encode(['verified' => $verified, 'url' => $shown, 'fetched_at' => gmdate(DATE_ATOM)], JSON_THROW_ON_ERROR)) !== false) {
            @rename($statusTmp, self::statusFile($file));
        }
        @unlink($statusTmp);

        return $file;
    }

    /** With an expected digest, a cached copy is only as good as its bytes: check them on every use. */
    private function requireExpectedDigest(string $file, string $shown): void
    {
        if ($this->expectedSha256 === null) {
            return;
        }
        $actual = hash_file('sha256', $file);
        if ($actual === false || !hash_equals(strtolower($this->expectedSha256), $actual)) {
            @unlink($file);
            @unlink(self::statusFile($file));
            throw new AdvisoryLookupFailed(sprintf('The cached advisory database from %s does not match the expected sha256 (expected %s, got %s); the copy was discarded.', $shown, $this->expectedSha256, $actual === false ? '?' : $actual));
        }
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
     * Verifies the download: against the operator's expected digest when one was given (the trust
     * anchor), otherwise against the publisher's `<url>.sha256` sidecar (a bare digest or `sha256sum`
     * output). A mismatch is fatal. No sidecar and no expected digest is fatal too unless the operator
     * chose to accept unverified downloads, in which case it is reported. Returns whether the download
     * was verified.
     */
    private function verifyChecksum(string $url, string $file): bool
    {
        $shown = self::redact($url);
        $actual = hash_file('sha256', $file);
        if ($this->expectedSha256 !== null) {
            if ($actual === false || !hash_equals(strtolower($this->expectedSha256), $actual)) {
                @unlink($file);
                throw new AdvisoryLookupFailed(sprintf('Advisory database %s does not match the expected sha256 (expected %s, got %s).', $shown, $this->expectedSha256, $actual === false ? '?' : $actual));
            }

            return true;
        }
        $sidecar = $file . '.sha256';
        try {
            $this->downloader->copy($url . '.sha256', $sidecar);
        } catch (TransportException $e) {
            @unlink($sidecar);
            if ($this->requireChecksum) {
                @unlink($file);
                throw new AdvisoryLookupFailed(sprintf('No checksum published next to %s (%s), so the download cannot be verified. Publish <url>.sha256 (the output of sha256sum), pass --database-sha256=<digest>, or pass --allow-unverified-database to accept it with a warning.', $shown, self::shortError($e)), 0, $e);
            }
            $this->warnings[] = sprintf('No checksum published next to %s (%s); the download was not verified against a sha256.', $shown, self::shortError($e));

            return false;
        }
        $published = trim((string) file_get_contents($sidecar));
        @unlink($sidecar);
        if (preg_match('{^([0-9a-f]{64})\b}i', $published, $m) !== 1) {
            @unlink($file);
            throw new AdvisoryLookupFailed(sprintf('The checksum file at %s.sha256 is not a sha256 digest.', $shown));
        }
        if ($actual === false || !hash_equals(strtolower($m[1]), $actual)) {
            @unlink($file);
            throw new AdvisoryLookupFailed(sprintf('Advisory database %s does not match its published sha256 (expected %s, got %s).', $shown, $m[1], $actual === false ? '?' : $actual));
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
