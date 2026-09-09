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

    public function testUnverifiedDownloadWarnsNowAndOnEveryCacheHit(): void
    {
        $url = 'https://example.test/advisories.sqlite';
        $first = new DatabaseLocator($this->composer(), $this->downloader([$url => 'bytes']));
        $file = $first->resolve($url);
        self::assertCount(1, $first->warnings());
        self::assertStringContainsString('not verified against a sha256', $first->warnings()[0]);

        // Fresh cache, new process: the disclosure must survive.
        $second = new DatabaseLocator($this->composer(), $this->downloader([], $requests));
        self::assertSame($file, $second->resolve($url));
        self::assertSame([], $requests, 'a fresh cache is not re-downloaded');
        self::assertCount(1, $second->warnings());
        self::assertStringContainsString('downloaded without a published sha256', $second->warnings()[0]);

        // Offline as well.
        $offline = new DatabaseLocator($this->composer(), $this->downloader([]), true);
        touch($file, time() - 2 * DatabaseLocator::TTL_SECONDS);
        $offline->resolve($url);
        self::assertCount(2, $offline->warnings(), 'stale-offline notice plus the verification disclosure');
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
