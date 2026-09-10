<?php

declare(strict_types=1);

namespace Remediate\Tests\Unit\Advisory;

use Composer\Composer;
use Composer\Config;
use Composer\Downloader\TransportException;
use Composer\IO\NullIO;
use Composer\Package\RootPackage;
use Composer\Util\HttpDownloader;
use PHPUnit\Framework\TestCase;
use Remediate\Engine\Advisory\AdvisoryLookupFailed;
use Remediate\Engine\Advisory\Db\DatabaseLocator;

/**
 * Download, checksum and cache behaviour of the locator, with a scripted HTTP layer: which URLs
 * answer, which fail, and what gets written.
 */
final class DatabaseLocatorTest extends TestCase
{
    private string $cacheDir;

    protected function setUp(): void
    {
        $this->cacheDir = sys_get_temp_dir() . '/composer-remediate-locator-' . bin2hex(random_bytes(4));
        mkdir($this->cacheDir, 0700, true);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->cacheDir . '/remediate/*') ?: [] as $file) {
            @unlink($file);
        }
        @rmdir($this->cacheDir . '/remediate');
        @rmdir($this->cacheDir);
    }

    private function composer(): Composer
    {
        $config = new Config(false);
        $config->merge(['config' => ['cache-dir' => $this->cacheDir]]);
        $composer = new Composer();
        $composer->setConfig($config);
        $composer->setPackage(new RootPackage('test/project', '1.0.0.0', '1.0.0'));

        return $composer;
    }

    /**
     * @param array<string, string|int> $responses url => body, or an HTTP status code to fail with
     * @param list<string>              $requests  receives every URL asked for
     * @param-out list<string> $requests
     */
    private function downloader(array $responses, ?array &$requests = null): HttpDownloader
    {
        $requests = [];

        return new class($responses, $requests) extends HttpDownloader {
            /**
             * @param array<string, string|int> $responses
             * @param list<string>              $requests
             */
            public function __construct(private readonly array $responses, private array &$requests)
            {
                parent::__construct(new NullIO(), new Config(false));
            }

            public function copy(string $url, string $to, array $options = []): \Composer\Util\Http\Response
            {
                $this->requests[] = $url;
                $response = $this->responses[$url] ?? 404;
                if (is_int($response)) {
                    throw new TransportException("The \"$url\" file could not be downloaded ($response)", $response);
                }
                file_put_contents($to, $response);

                return new \Composer\Util\Http\Response(['url' => $url === '' ? 'x' : $url], 200, [], null);
            }

            /** @return list<string> */
            public function requested(): array
            {
                return $this->requests;
            }
        };
    }

    public function testVerifiedDownloadIsSilentAndStaysSilentFromCache(): void
    {
        $url = 'https://example.test/advisories.sqlite';
        $body = 'sqlite-bytes';
        $downloader = $this->downloader([$url => $body, $url . '.sha256' => hash('sha256', $body) . '  advisories.sqlite']);
        $locator = new DatabaseLocator($this->composer(), $downloader);
        $file = $locator->resolve($url);
        self::assertStringEqualsFile($file, $body);
        self::assertSame([], $locator->warnings());

        $again = new DatabaseLocator($this->composer(), $this->downloader([]));
        self::assertSame($file, $again->resolve($url));
        self::assertSame([], $again->warnings());
    }

    public function testMismatchedChecksumIsFatalAndLeavesNoCache(): void
    {
        $url = 'https://example.test/advisories.sqlite';
        $downloader = $this->downloader([$url => 'tampered', $url . '.sha256' => str_repeat('0', 64)]);
        $locator = new DatabaseLocator($this->composer(), $downloader);
        try {
            $locator->resolve($url);
            self::fail('expected a checksum failure');
        } catch (AdvisoryLookupFailed $e) {
            self::assertStringContainsString('does not match its published sha256', $e->getMessage());
        }
        self::assertSame([], glob($this->cacheDir . '/remediate/db-*.sqlite') ?: []);
    }

    public function testADownloadWithoutAnyChecksumIsRefusedByDefault(): void
    {
        $url = 'https://example.test/advisories.sqlite';
        $locator = new DatabaseLocator($this->composer(), $this->downloader([$url => 'bytes']));
        try {
            $locator->resolve($url);
            self::fail('expected the unverifiable download to be refused');
        } catch (AdvisoryLookupFailed $e) {
            self::assertStringContainsString('No checksum published next to https://example.test/advisories.sqlite', $e->getMessage());
            self::assertStringContainsString('--database-sha256=<digest>', $e->getMessage());
            self::assertStringContainsString('--allow-unverified-database', $e->getMessage());
        }
        self::assertSame([], glob($this->cacheDir . '/remediate/db-*.sqlite') ?: [], 'nothing unverified is cached');
    }

    public function testUnverifiedDownloadWarnsNowAndOnEveryCacheHitWhenExplicitlyAllowed(): void
    {
        $url = 'https://example.test/advisories.sqlite';
        $first = new DatabaseLocator($this->composer(), $this->downloader([$url => 'bytes']), false, false);
        $file = $first->resolve($url);
        self::assertCount(1, $first->warnings());
        self::assertStringContainsString('not verified against a sha256', $first->warnings()[0]);

        // Fresh cache, new process: the disclosure must survive.
        $second = new DatabaseLocator($this->composer(), $this->downloader([], $requests), false, false);
        self::assertSame($file, $second->resolve($url));
        self::assertSame([], $requests, 'a fresh cache is not re-downloaded');
        self::assertCount(1, $second->warnings());
        self::assertStringContainsString('downloaded without a published sha256', $second->warnings()[0]);

        // Offline as well.
        $offline = new DatabaseLocator($this->composer(), $this->downloader([]), true, false);
        touch($file, time() - 2 * DatabaseLocator::TTL_SECONDS);
        $offline->resolve($url);
        self::assertCount(2, $offline->warnings(), 'stale-offline notice plus the verification disclosure');
    }

    public function testAnExpectedDigestIsTheTrustAnchorAndIsCheckedOnEveryCacheUse(): void
    {
        $url = 'https://example.test/advisories.sqlite';
        $body = 'trusted-bytes';
        $digest = hash('sha256', $body);
        // No sidecar at all: the operator's digest alone verifies the download.
        $locator = new DatabaseLocator($this->composer(), $this->downloader([$url => $body], $requests), false, true, $digest);
        $file = $locator->resolve($url);
        self::assertStringEqualsFile($file, $body);
        self::assertSame([], $locator->warnings());
        self::assertSame([$url], $requests, 'the sidecar is not even fetched');

        // A wrong digest refuses the download and leaves no cache.
        $wrong = new DatabaseLocator($this->composer(), $this->downloader([$url => $body]), false, true, str_repeat('a', 64));
        @unlink($file);
        try {
            $wrong->resolve($url);
            self::fail('expected a digest mismatch');
        } catch (AdvisoryLookupFailed $e) {
            self::assertStringContainsString('does not match the expected sha256', $e->getMessage());
        }
        self::assertSame([], glob($this->cacheDir . '/remediate/db-*.sqlite') ?: []);

        // A cached copy that no longer matches the expected digest is discarded, even when fresh.
        $file = $locator->resolve($url);
        file_put_contents($file, 'tampered on disk');
        $again = new DatabaseLocator($this->composer(), $this->downloader([]), false, true, $digest);
        try {
            $again->resolve($url);
            self::fail('expected the tampered cache to be refused');
        } catch (AdvisoryLookupFailed $e) {
            self::assertStringContainsString('cached advisory database', $e->getMessage());
            self::assertStringContainsString('discarded', $e->getMessage());
        }
        self::assertFileDoesNotExist($file);
    }

    public function testOnlyHttpsUrlsAreDownloaded(): void
    {
        $locator = new DatabaseLocator($this->composer(), $this->downloader(['http://internal.test/advisories.sqlite' => 'bytes'], $requests));
        try {
            $locator->resolve('http://internal.test/advisories.sqlite');
            self::fail('expected the http URL to be refused');
        } catch (AdvisoryLookupFailed $e) {
            self::assertStringContainsString('only https:// URLs are downloaded', $e->getMessage());
        }
        self::assertSame([], $requests, 'no request is made');
        $this->expectException(AdvisoryLookupFailed::class);
        $locator->resolve('ftp://internal.test/advisories.sqlite');
    }

    public function testASymbolicLinkInTheCacheIsRefused(): void
    {
        $url = 'https://example.test/advisories.sqlite';
        mkdir($this->cacheDir . '/remediate', 0700, true);
        $victim = $this->cacheDir . '/victim';
        file_put_contents($victim, 'do not touch');
        symlink($victim, $this->cacheDir . '/remediate/db-' . sha1($url) . '.sqlite.status.json');
        $locator = new DatabaseLocator($this->composer(), $this->downloader([$url => 'bytes', $url . '.sha256' => hash('sha256', 'bytes')]));
        try {
            $locator->resolve($url);
            self::fail('expected the symlinked cache entry to be refused');
        } catch (AdvisoryLookupFailed $e) {
            self::assertStringContainsString('is a symbolic link', $e->getMessage());
        }
        self::assertStringEqualsFile($victim, 'do not touch');
        @unlink($this->cacheDir . '/remediate/db-' . sha1($url) . '.sqlite.status.json');
        @unlink($victim);
    }

    public function testCredentialsInTheUrlNeverReachMessagesOrTheCacheMetadata(): void
    {
        $url = 'https://deploy:s3cret@example.test/advisories.sqlite';
        $locator = new DatabaseLocator($this->composer(), $this->downloader([$url => 'bytes']), false, false);
        $file = $locator->resolve($url);
        self::assertStringNotContainsString('s3cret', implode("\n", $locator->warnings()));
        self::assertStringContainsString('https://***@example.test/advisories.sqlite', $locator->warnings()[0]);
        self::assertStringNotContainsString('s3cret', (string) file_get_contents($file . '.status.json'));

        $failing = new DatabaseLocator($this->composer(), $this->downloader(['https://deploy:s3cret@example.test/missing.sqlite' => 500]));
        try {
            $failing->resolve('https://deploy:s3cret@example.test/missing.sqlite');
            self::fail('expected the download to fail');
        } catch (AdvisoryLookupFailed $e) {
            self::assertStringNotContainsString('s3cret', $e->getMessage());
        }
        self::assertSame('see https://***@h/x and https://***@h/y', DatabaseLocator::redact('see https://a:b@h/x and https://c@h/y'));
    }

    public function testFailedRefreshReusesStaleCopyWithAWarning(): void
    {
        $url = 'https://example.test/advisories.sqlite';
        $first = new DatabaseLocator($this->composer(), $this->downloader([$url => 'v1', $url . '.sha256' => hash('sha256', 'v1')]));
        $file = $first->resolve($url);
        touch($file, time() - 2 * DatabaseLocator::TTL_SECONDS);

        $refresh = new DatabaseLocator($this->composer(), $this->downloader([$url => 503]));
        self::assertSame($file, $refresh->resolve($url));
        self::assertStringEqualsFile($file, 'v1');
        self::assertCount(1, $refresh->warnings());
        self::assertStringContainsString('refresh failed (HTTP 503)', $refresh->warnings()[0]);
    }

    public function testNoCacheAndNoNetworkIsFatal(): void
    {
        $locator = new DatabaseLocator($this->composer(), $this->downloader(['https://example.test/x.sqlite' => 500]));
        $this->expectException(AdvisoryLookupFailed::class);
        $locator->resolve('https://example.test/x.sqlite');
    }
}
