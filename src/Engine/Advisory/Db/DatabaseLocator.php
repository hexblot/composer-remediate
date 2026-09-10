<?php

declare(strict_types=1);

namespace Remediate\Engine\Advisory\Db;

use Composer\Composer;
use Composer\Downloader\TransportException;
use Composer\Util\HttpDownloader;
use Remediate\Engine\Advisory\AdvisoryLookupFailed;

/**
 * Keeps the advisory database at its path current and says how it was established as the one to read.
 *
 * Every run with a database checks the local file against the configured sources, in order: the
 * publisher's `latest.json` (sha256, dataset hash, publication time) or, failing that, its `<url>.sha256`
 * sidecar. A local file with the same sha256 is the published database itself; one with the same
 * dataset hash is a local build of the same data; one built after the publication is a newer local
 * build. Each of those is current and used. Anything else is replaced by a download (or, on request,
 * by a rebuild from the sources). When no source can be reached, the local copy is used and the report
 * says so with the copy's age, unless it is older than the configured maximum age, in which case the
 * run fails rather than gate on data of unknown staleness.
 *
 * Downloads are verified against the publisher's digest; a mismatch is fatal. A file that is not a
 * readable advisory database is replaced. Symbolic links at any of the paths written are refused.
 */
final class DatabaseLocator
{
    public const ENV = DatabaseSettings::ENV_LOCATION;

    /** @var list<string> */
    private array $warnings = [];

    /**
     * @param bool        $requireChecksum refuse a download that no published digest or expected digest verifies (the
     *                                     default); false accepts it with a warning in the report
     * @param string|null $expectedSha256  the digest the operator trusts (hex); a download or local copy that differs is
     *                                     refused. The publisher's digest is only as trustworthy as the host that serves
     *                                     both, so this is the real trust anchor for a URL you do not publish yourself
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

    /** Where the database lives by default and where builds write their temporary files. */
    public function cacheDirectory(): string
    {
        $dir = $this->composer->getConfig()->get('cache-dir');

        return rtrim(is_string($dir) && $dir !== '' ? $dir : sys_get_temp_dir(), '/') . '/remediate';
    }

    public function defaultBuildPath(): string
    {
        return $this->cacheDirectory() . '/advisories.sqlite';
    }

    /**
     * The three settings resolved from options, environment and composer.json.
     *
     * @throws \InvalidArgumentException for a max age that is not a duration
     */
    public function settings(?string $location = null, ?string $path = null, ?string $maxAge = null, bool $noDatabase = false): DatabaseSettings
    {
        return DatabaseSettings::resolve($this->composer, $this->defaultBuildPath(), $location, $path, $maxAge, $noDatabase);
    }

    /** The configured source (option, environment, composer.json), or null when none is configured. */
    public function configured(?string $option): ?string
    {
        $settings = $this->settings($option);
        if (!$settings->sourcesConfigured) {
            return null;
        }

        return $settings->usesDatabase() ? implode(',', $settings->sources) : 'composer';
    }

    /**
     * Establishes the database to read, or null when no database is usable and the caller should fall
     * back (or fail): the settings name no database, the file is missing and no source can be reached,
     * or offline mode finds no file. Soft outcomes are explained in warnings(); hard refusals (a digest
     * mismatch, an unverifiable download, a symbolic link, a non-https source, a copy older than the
     * maximum age) throw.
     *
     * @param callable(string): void|null $rebuild builds the database at the given path from the sources instead of
     *                                             downloading, when the local copy is missing or stale
     *
     * @throws AdvisoryLookupFailed
     */
    public function locate(DatabaseSettings $settings, ?callable $rebuild = null): ?LocatedDatabase
    {
        if (!$settings->usesDatabase()) {
            return null;
        }
        $explicit = $settings->localSource();
        if ($explicit !== null) {
            return new LocatedDatabase($this->resolveLocalPath($explicit), Freshness::Explicit, 'a local file named by --database-location, read as it is');
        }
        $path = $settings->path;
        $dir = dirname($path);
        @mkdir($dir, 0700, true);
        $this->refuseLinks([$dir, $path, self::statusFile($path)]);

        $local = $this->inspect($path);
        if ($this->offline) {
            if ($local === null) {
                $this->warnings[] = sprintf('Offline mode and no advisory database at %s.', $path);

                return null;
            }
            $this->requireExpectedDigest($path, $local['sha256']);
            $this->enforceMaxAge($local, $settings, 'offline');
            $this->recallVerification($path);
            $this->warnings[] = sprintf('Offline: using the advisory database at %s built %s; advisories published since then are unknown to this run.', $path, self::age($local));

            return new LocatedDatabase($path, Freshness::Offline, sprintf('offline, using the copy built %s', self::age($local)));
        }

        $failures = [];
        foreach ($settings->sources as $source) {
            $shown = self::redact($source);
            if (preg_match('{^https://}i', $source) !== 1) {
                // Advisory data decides a security gate: only TLS-protected downloads are accepted. This also
                // keeps a composer.json-configured location from pointing the tool at an internal http service.
                throw new AdvisoryLookupFailed(sprintf('Advisory database location %s is not an https URL or a local path; only https:// URLs are downloaded.', $shown));
            }
            $remote = $this->remoteMeta($source, $reason);
            if ($remote === null) {
                if ($local === null && $rebuild !== null) {
                    // The publisher cannot be asked, but the sources can: build rather than run without a database.
                    try {
                        $rebuild($path);
                        $fresh = $this->inspect($path);
                        if ($fresh !== null) {
                            $this->requireExpectedDigest($path, $fresh['sha256']);
                            $this->warnings[] = sprintf('Could not reach %s (%s); the advisory database was built from the sources instead.', $shown, (string) $reason);

                            return new LocatedDatabase($path, Freshness::Rebuilt, sprintf('rebuilt from the sources (%s unreachable: %s)', $shown, (string) $reason));
                        }
                    } catch (\RuntimeException $e) {
                        if ($e instanceof AdvisoryLookupFailed) {
                            throw $e;
                        }
                        $failures[] = sprintf('rebuild: %s', self::redact(trim(explode("\n", $e->getMessage())[0])));
                    }
                } elseif ($local === null && !$this->requireChecksum && str_starts_with((string) $reason, 'HTTP 4')) {
                    // Nothing published to verify against, and the operator accepts that: download anyway, disclosed.
                    try {
                        $this->download($source, $path, ['sha256' => null, 'datasetHash' => null, 'publishedAt' => null]);

                        return new LocatedDatabase($path, Freshness::Downloaded, sprintf('downloaded from %s without verification (no local copy)', $shown));
                    } catch (TransportException $e) {
                        $failures[] = sprintf('%s: %s', $shown, self::shortError($e));
                        continue;
                    }
                }
                $failures[] = sprintf('%s: %s%s', $shown, (string) $reason, $local === null && $this->requireChecksum && str_starts_with((string) $reason, 'HTTP 4') ? ' (no latest.json or .sha256 published there; pass --allow-unverified-database to download it anyway)' : '');
                continue;
            }
            if ($local !== null) {
                $why = self::currency($local, $remote);
                if ($why !== null) {
                    $this->requireExpectedDigest($path, $local['sha256']);
                    if ($why !== 'same sha256 as the published database') {
                        $this->recallVerification($path);
                    }

                    return new LocatedDatabase($path, Freshness::Confirmed, sprintf('confirmed current against %s (%s), built %s', $shown, $why, self::age($local)));
                }
            }
            $reasonToRefresh = $local === null ? 'no local copy' : sprintf('the copy built %s is not the published one', self::age($local));
            try {
                if ($rebuild !== null) {
                    $rebuild($path);
                    $fresh = $this->inspect($path);
                    if ($fresh === null) {
                        throw new AdvisoryLookupFailed(sprintf('The rebuild left no readable advisory database at %s.', $path));
                    }
                    $this->requireExpectedDigest($path, $fresh['sha256']);

                    return new LocatedDatabase($path, Freshness::Rebuilt, sprintf('rebuilt from the sources (%s)', $reasonToRefresh));
                }
                $this->download($source, $path, $remote);

                return new LocatedDatabase($path, Freshness::Downloaded, sprintf('downloaded from %s (%s)', $shown, $reasonToRefresh));
            } catch (TransportException $e) {
                $failures[] = sprintf('%s: %s', $shown, self::shortError($e));
            } catch (\RuntimeException $e) {
                if ($e instanceof AdvisoryLookupFailed) {
                    throw $e;
                }
                $failures[] = sprintf('rebuild: %s', self::redact(trim(explode("\n", $e->getMessage())[0])));
            }
        }

        $what = implode('; ', $failures);
        if ($local !== null) {
            $this->requireExpectedDigest($path, $local['sha256']);
            $this->enforceMaxAge($local, $settings, $what);
            $this->recallVerification($path);
            $this->warnings[] = sprintf('Could not confirm that the advisory database at %s is current (%s); using the copy built %s. Advisories published since then are unknown to this run.', $path, $what, self::age($local));

            return new LocatedDatabase($path, Freshness::Unconfirmed, sprintf('could not be confirmed current (%s), using the copy built %s', $what, self::age($local)));
        }
        $this->warnings[] = sprintf('No advisory database at %s and none could be fetched (%s).', $path, $what);

        return null;
    }

    /**
     * Turns a single configured location into a file to read: a local path as it is, an https URL through
     * the default path with the freshness check.
     *
     * @throws AdvisoryLookupFailed when nothing usable results
     */
    public function resolve(string $location): string
    {
        $located = $this->locate($this->settings($location));
        if ($located === null) {
            throw new AdvisoryLookupFailed($this->warnings === [] ? sprintf('Advisory database %s is not available.', self::redact($location)) : $this->warnings[count($this->warnings) - 1]);
        }

        return $located->path;
    }

    /**
     * Conditions under which the resolved database is weaker than it looks (unconfirmed copy after a
     * failed check, download without a checksum), to be shown with the report.
     *
     * @return list<string>
     */
    public function warnings(): array
    {
        return $this->warnings;
    }

    private function resolveLocalPath(string $location): string
    {
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

    /** @param list<string> $paths */
    private function refuseLinks(array $paths): void
    {
        // The directory may be shared (Composer's cache under a shared HOME, or the temp dir as a last
        // resort). A symlink planted at one of the predictable names would make this process write
        // through it into a file of the attacker's choosing, so every path is checked first.
        foreach ($paths as $path) {
            if (is_link($path)) {
                throw new AdvisoryLookupFailed(sprintf('Refusing to use the advisory database path: %s is a symbolic link.', $path));
            }
        }
    }

    /**
     * What is at the path: its digest and, when it is a readable advisory database, its dataset hash and
     * build time. Null when there is no file; a file that is not a database is reported and treated as absent.
     *
     * @return array{sha256: string, datasetHash: ?string, builtAt: ?int, mtime: int}|null
     */
    private function inspect(string $path): ?array
    {
        if (!is_file($path)) {
            return null;
        }
        $sha = hash_file('sha256', $path);
        try {
            $meta = Database::open($path)->meta();
        } catch (AdvisoryLookupFailed $e) {
            $this->warnings[] = sprintf('%s is not a readable advisory database (%s); it will be replaced.', $path, trim(explode("\n", $e->getMessage())[0]));

            return null;
        }
        $builtAt = isset($meta['built_at']) ? strtotime($meta['built_at']) : false;

        return ['sha256' => $sha === false ? '' : $sha, 'datasetHash' => $meta['dataset_hash'] ?? null, 'builtAt' => $builtAt === false ? null : $builtAt, 'mtime' => (int) filemtime($path)];
    }

    /**
     * What the publisher says about the current database: `<dir>/latest.json` (sha256, dataset_hash,
     * published_at) when it exists, else the `<url>.sha256` sidecar. Null with $reason when neither answers.
     *
     * @return array{sha256: ?string, datasetHash: ?string, publishedAt: ?int}|null
     */
    private function remoteMeta(string $url, ?string &$reason): ?array
    {
        $reason = null;
        $tmp = tempnam(sys_get_temp_dir(), 'remediate-meta-');
        if ($tmp === false) {
            $reason = 'cannot create a temporary file';

            return null;
        }
        try {
            $latest = preg_replace('{/[^/]*$}', '/latest.json', $url) ?? '';
            try {
                $this->downloader->copy($latest, $tmp);
                $decoded = json_decode((string) file_get_contents($tmp), true);
                if (is_array($decoded) && is_string($decoded['sha256'] ?? null)) {
                    $publishedAt = is_string($decoded['published_at'] ?? null) ? strtotime($decoded['published_at']) : false;

                    return ['sha256' => strtolower($decoded['sha256']), 'datasetHash' => is_string($decoded['dataset_hash'] ?? null) ? $decoded['dataset_hash'] : null, 'publishedAt' => $publishedAt === false ? null : $publishedAt];
                }
            } catch (TransportException) {
                // no latest.json: a plain mirror; the sidecar decides
            }
            try {
                $this->downloader->copy($url . '.sha256', $tmp);
            } catch (TransportException $e) {
                $reason = self::shortError($e);

                return null;
            }
            $digest = self::digestFrom((string) file_get_contents($tmp));
            if ($digest === null) {
                throw new AdvisoryLookupFailed(sprintf('The checksum file at %s.sha256 is not a sha256 digest.', self::redact($url)));
            }

            return ['sha256' => $digest, 'datasetHash' => null, 'publishedAt' => null];
        } finally {
            @unlink($tmp);
        }
    }

    /**
     * Why the local copy counts as current against what the publisher says, or null when it does not.
     *
     * @param array{sha256: string, datasetHash: ?string, builtAt: ?int, mtime: int} $local
     * @param array{sha256: ?string, datasetHash: ?string, publishedAt: ?int}        $remote
     */
    private static function currency(array $local, array $remote): ?string
    {
        if ($remote['sha256'] !== null && $local['sha256'] !== '' && hash_equals($remote['sha256'], $local['sha256'])) {
            return 'same sha256 as the published database';
        }
        if ($remote['datasetHash'] !== null && $local['datasetHash'] !== null && $local['datasetHash'] !== '' && hash_equals($remote['datasetHash'], $local['datasetHash'])) {
            return 'same dataset hash as the published database';
        }
        if ($remote['publishedAt'] !== null && $local['builtAt'] !== null && $local['builtAt'] > $remote['publishedAt']) {
            return 'a local build newer than the published database';
        }

        return null;
    }

    /**
     * Downloads the database beside the path and moves it into place once verified: against the
     * operator's expected digest when given (the trust anchor), else the publisher's digest from
     * latest.json or the sidecar. A mismatch is retried once against the sidecar (the publisher may have
     * moved between the two requests), then is fatal. No digest at all is fatal unless unverified
     * downloads were accepted, in which case the report says so.
     *
     * @param array{sha256: ?string, datasetHash: ?string, publishedAt: ?int} $remote
     *
     * @throws TransportException when the download itself fails
     */
    private function download(string $url, string $path, array $remote): void
    {
        $shown = self::redact($url);
        $tmp = $path . '.tmp-' . bin2hex(random_bytes(8));
        try {
            $this->downloader->copy($url, $tmp);
        } catch (TransportException $e) {
            @unlink($tmp);
            throw $e;
        }
        $actual = hash_file('sha256', $tmp);
        $actual = $actual === false ? '' : $actual;
        $verified = true;
        if ($this->expectedSha256 !== null) {
            if (!hash_equals(strtolower($this->expectedSha256), $actual)) {
                @unlink($tmp);
                throw new AdvisoryLookupFailed(sprintf('Advisory database %s does not match the expected sha256 (expected %s, got %s).', $shown, $this->expectedSha256, $actual));
            }
        } elseif ($remote['sha256'] !== null) {
            if (!hash_equals($remote['sha256'], $actual)) {
                $sidecar = $this->sidecarDigest($url);
                if ($sidecar === null || !hash_equals($sidecar, $actual)) {
                    @unlink($tmp);
                    throw new AdvisoryLookupFailed(sprintf('Advisory database %s does not match its published sha256 (expected %s, got %s).', $shown, $sidecar ?? $remote['sha256'], $actual));
                }
            }
        } elseif ($this->requireChecksum) {
            @unlink($tmp);
            throw new AdvisoryLookupFailed(sprintf('No checksum published next to %s, so the download cannot be verified. Publish <url>.sha256 (the output of sha256sum) or latest.json, pass --database-sha256=<digest>, or pass --allow-unverified-database to accept it with a warning.', $shown));
        } else {
            $verified = false;
            $this->warnings[] = sprintf('No checksum published next to %s; the download was not verified against a sha256.', $shown);
        }
        if (!@rename($tmp, $path)) {
            @unlink($tmp);
            throw new AdvisoryLookupFailed(sprintf('Could not store the downloaded advisory database in %s.', $path));
        }
        // The verification outcome is a property of the bytes, not of this request: record it so every
        // later run that reuses the copy repeats the disclosure. Written atomically, never through an
        // existing link (checked by the caller), and without the URL's credentials.
        $statusTmp = self::statusFile($path) . '.tmp-' . bin2hex(random_bytes(8));
        if (@file_put_contents($statusTmp, json_encode(['verified' => $verified, 'url' => $shown, 'fetched_at' => gmdate(DATE_ATOM)], JSON_THROW_ON_ERROR)) !== false) {
            @rename($statusTmp, self::statusFile($path));
        }
        @unlink($statusTmp);
    }

    private function sidecarDigest(string $url): ?string
    {
        $tmp = tempnam(sys_get_temp_dir(), 'remediate-sha-');
        if ($tmp === false) {
            return null;
        }
        try {
            $this->downloader->copy($url . '.sha256', $tmp);

            return self::digestFrom((string) file_get_contents($tmp));
        } catch (TransportException) {
            return null;
        } finally {
            @unlink($tmp);
        }
    }

    /** A bare digest or `sha256sum` output, lower-cased; null for anything else. */
    private static function digestFrom(string $text): ?string
    {
        return preg_match('{^([0-9a-f]{64})\b}i', trim($text), $m) === 1 ? strtolower($m[1]) : null;
    }

    /** With an expected digest, a copy is only as good as its bytes: check them on every use. */
    private function requireExpectedDigest(string $path, string $actual): void
    {
        if ($this->expectedSha256 === null) {
            return;
        }
        if ($actual === '' || !hash_equals(strtolower($this->expectedSha256), $actual)) {
            @unlink($path);
            @unlink(self::statusFile($path));
            throw new AdvisoryLookupFailed(sprintf('The advisory database at %s does not match the expected sha256 (expected %s, got %s); the copy was discarded.', $path, $this->expectedSha256, $actual === '' ? '?' : $actual));
        }
    }

    /**
     * A copy that could not be confirmed current may not be older than the configured maximum.
     *
     * @param array{sha256: string, datasetHash: ?string, builtAt: ?int, mtime: int} $local
     */
    private function enforceMaxAge(array $local, DatabaseSettings $settings, string $context): void
    {
        if ($settings->maxAgeSeconds === null) {
            return;
        }
        $age = time() - ($local['builtAt'] ?? $local['mtime']);
        if ($age > $settings->maxAgeSeconds) {
            throw new AdvisoryLookupFailed(sprintf('The advisory database at %s was built %s, older than the allowed %s, and could not be refreshed (%s).', $settings->path, self::age($local), self::duration($settings->maxAgeSeconds), $context));
        }
    }

    private static function statusFile(string $file): string
    {
        return $file . '.status.json';
    }

    /** Re-emits the disclosure recorded when the copy was downloaded; a copy built locally has none. */
    private function recallVerification(string $file): void
    {
        $raw = @file_get_contents(self::statusFile($file));
        $status = is_string($raw) ? json_decode($raw, true) : null;
        if (is_array($status) && array_key_exists('verified', $status) && $status['verified'] !== true) {
            $this->warnings[] = sprintf('The copy of %s in use was downloaded without a published sha256 to verify against (%s).', is_string($status['url'] ?? null) ? $status['url'] : $file, is_string($status['fetched_at'] ?? null) ? 'fetched ' . $status['fetched_at'] : 'date unknown');
        }
    }

    /** @param array{sha256: string, datasetHash: ?string, builtAt: ?int, mtime: int} $local */
    private static function age(array $local): string
    {
        $seconds = max(0, time() - ($local['builtAt'] ?? $local['mtime']));

        return self::duration($seconds) . ' ago';
    }

    private static function duration(int $seconds): string
    {
        if ($seconds < 3600 * 48) {
            $hours = intdiv($seconds, 3600);

            return sprintf('%d hour%s', $hours, $hours === 1 ? '' : 's');
        }
        $days = intdiv($seconds, 86400);

        return sprintf('%d day%s', $days, $days === 1 ? '' : 's');
    }

    private static function shortError(\Throwable $e): string
    {
        $code = $e->getCode();

        return $code !== 0 ? sprintf('HTTP %d', $code) : self::redact(trim(explode("\n", $e->getMessage())[0]));
    }
}
