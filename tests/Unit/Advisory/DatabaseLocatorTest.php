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
use Remediate\Engine\Advisory\Db\DatabaseSettings;
use Remediate\Engine\Advisory\Db\Freshness;

/**
 * The freshness check, download, verification and fallback behaviour of the locator, with a scripted
 * HTTP layer: which URLs answer, which fail, and what ends up at the database path.
 */
final class DatabaseLocatorTest extends TestCase
{
    private const URL = 'https://example.test/db/advisories.sqlite';
    private const LATEST = 'https://example.test/db/latest.json';

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

    /** @param array<string, mixed> $extra */
    private function composer(array $extra = []): Composer
    {
        $config = new Config(false);
        $config->merge(['config' => ['cache-dir' => $this->cacheDir]]);
        $composer = new Composer();
        $composer->setConfig($config);
        $package = new RootPackage('test/project', '1.0.0.0', '1.0.0');
        $package->setExtra($extra);
        $composer->setPackage($package);

        return $composer;
    }

    private function path(): string
    {
        return $this->cacheDir . '/remediate/advisories.sqlite';
    }

    /** The bytes of a minimal advisory database with the given metadata. */
    private static function database(string $datasetHash, string $builtAt): string
    {
        $tmp = tempnam(sys_get_temp_dir(), 'remediate-db-');
        self::assertNotFalse($tmp);
        @unlink($tmp);
        $pdo = new \PDO('sqlite:' . $tmp, null, null, [\PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION]);
        $pdo->exec('CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)');
        $insert = $pdo->prepare('INSERT INTO meta VALUES (?, ?)');
        foreach (['schema_version' => '1', 'built_at' => $builtAt, 'dataset_hash' => $datasetHash, 'advisory_count' => '1'] as $k => $v) {
            $insert->execute([$k, $v]);
        }
        $pdo = null;
        $bytes = (string) file_get_contents($tmp);
        @unlink($tmp);

        return $bytes;
    }

    /** @return array<string, string> the two files a publisher exposes next to the database */
    private static function published(string $bytes, string $datasetHash, string $publishedAt): array
    {
        return [
            self::LATEST => json_encode(['sha256' => hash('sha256', $bytes), 'dataset_hash' => $datasetHash, 'published_at' => $publishedAt], JSON_THROW_ON_ERROR),
            self::URL . '.sha256' => hash('sha256', $bytes) . '  advisories.sqlite',
        ];
    }

    private static function hoursAgo(int $hours): string
    {
        return gmdate(DATE_ATOM, time() - $hours * 3600);
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
            public function __construct(
                private readonly array $responses,
                /** @phpstan-ignore property.onlyWritten (read through the caller's reference) */
                private array &$requests,
            ) {
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
        };
    }

    private function settings(DatabaseLocator $locator, string $location = self::URL, ?string $maxAge = null): DatabaseSettings
    {
        return $locator->settings($location, $this->path(), $maxAge);
    }

    public function testAMissingCopyIsDownloadedAndVerifiedAgainstLatestJson(): void
    {
        $bytes = self::database('h1', self::hoursAgo(1));
        $downloader = $this->downloader([self::URL => $bytes] + self::published($bytes, 'h1', self::hoursAgo(1)), $requests);
        $locator = new DatabaseLocator($this->composer(), $downloader);

        $located = $locator->locate($this->settings($locator));

        self::assertNotNull($located);
        self::assertSame(Freshness::Downloaded, $located->freshness);
        self::assertSame($this->path(), $located->path);
        self::assertStringEqualsFile($this->path(), $bytes);
        self::assertStringContainsString('no local copy', $located->provenance);
        self::assertSame([], $locator->warnings());
        self::assertSame([self::LATEST, self::URL], $requests, 'latest.json carries the digest, so the sidecar is not fetched');
    }

    public function testAMirrorWithoutLatestJsonIsVerifiedThroughTheSidecar(): void
    {
        $bytes = self::database('h1', self::hoursAgo(1));
        $locator = new DatabaseLocator($this->composer(), $this->downloader([self::URL => $bytes, self::URL . '.sha256' => hash('sha256', $bytes)], $requests));

        $located = $locator->locate($this->settings($locator));

        self::assertSame(Freshness::Downloaded, $located?->freshness);
        self::assertSame([self::LATEST, self::URL . '.sha256', self::URL], $requests);
        self::assertSame([], $locator->warnings());
    }

    public function testACopyWithThePublishedSha256IsConfirmedWithoutDownloading(): void
    {
        $bytes = self::database('h1', self::hoursAgo(1));
        mkdir(dirname($this->path()), 0700, true);
        file_put_contents($this->path(), $bytes);
        $locator = new DatabaseLocator($this->composer(), $this->downloader(self::published($bytes, 'h1', self::hoursAgo(1)), $requests));

        $located = $locator->locate($this->settings($locator));

        self::assertSame(Freshness::Confirmed, $located?->freshness);
        self::assertStringContainsString('same sha256 as the published database', $located->provenance);
        self::assertSame([self::LATEST], $requests);
        self::assertSame([], $locator->warnings());
    }

    public function testALocalBuildWithTheSameDatasetHashIsCurrent(): void
    {
        $local = self::database('h1', self::hoursAgo(2));
        $published = self::database('h1', self::hoursAgo(1)); // same data, different bytes (built_at differs)
        mkdir(dirname($this->path()), 0700, true);
        file_put_contents($this->path(), $local);
        $locator = new DatabaseLocator($this->composer(), $this->downloader([self::URL => $published] + self::published($published, 'h1', self::hoursAgo(1)), $requests));

        $located = $locator->locate($this->settings($locator));

        self::assertSame(Freshness::Confirmed, $located?->freshness);
        self::assertStringContainsString('same dataset hash', $located->provenance);
        self::assertStringEqualsFile($this->path(), $local, 'the local build is kept');
        self::assertNotContains(self::URL, $requests);
    }

    public function testANewerLocalBuildIsCurrentEvenWithADifferentDataset(): void
    {
        $local = self::database('h-private', self::hoursAgo(0));
        $published = self::database('h1', self::hoursAgo(5));
        mkdir(dirname($this->path()), 0700, true);
        file_put_contents($this->path(), $local);
        $locator = new DatabaseLocator($this->composer(), $this->downloader([self::URL => $published] + self::published($published, 'h1', self::hoursAgo(5))));

        $located = $locator->locate($this->settings($locator));

        self::assertSame(Freshness::Confirmed, $located?->freshness);
        self::assertStringContainsString('newer than the published database', $located->provenance);
        self::assertStringEqualsFile($this->path(), $local);
    }

    public function testAStaleCopyIsReplacedByTheDownload(): void
    {
        $stale = self::database('h0', self::hoursAgo(48));
        $published = self::database('h1', self::hoursAgo(1));
        mkdir(dirname($this->path()), 0700, true);
        file_put_contents($this->path(), $stale);
        $locator = new DatabaseLocator($this->composer(), $this->downloader([self::URL => $published] + self::published($published, 'h1', self::hoursAgo(1))));

        $located = $locator->locate($this->settings($locator));

        self::assertSame(Freshness::Downloaded, $located?->freshness);
        self::assertStringContainsString('is not the published one', $located->provenance);
        self::assertStringEqualsFile($this->path(), $published);
        self::assertSame([], $locator->warnings());
    }

    public function testAnUnreachableSourceKeepsTheCopyAndSaysSo(): void
    {
        $bytes = self::database('h1', self::hoursAgo(30));
        mkdir(dirname($this->path()), 0700, true);
        file_put_contents($this->path(), $bytes);
        $locator = new DatabaseLocator($this->composer(), $this->downloader([self::LATEST => 503, self::URL . '.sha256' => 503]));

        $located = $locator->locate($this->settings($locator));

        self::assertSame(Freshness::Unconfirmed, $located?->freshness);
        self::assertStringEqualsFile($this->path(), $bytes);
        self::assertCount(1, $locator->warnings());
        self::assertStringContainsString('Could not confirm that the advisory database at ' . $this->path() . ' is current', $locator->warnings()[0]);
        self::assertStringContainsString('HTTP 503', $locator->warnings()[0]);
        self::assertStringContainsString('built 30 hours ago', $locator->warnings()[0]);
    }

    public function testAnUnreachableSourceAndNoCopyYieldsNothingWithAnExplanation(): void
    {
        $locator = new DatabaseLocator($this->composer(), $this->downloader([self::LATEST => 500, self::URL . '.sha256' => 500]));

        self::assertNull($locator->locate($this->settings($locator)));
        self::assertCount(1, $locator->warnings());
        self::assertStringContainsString('No advisory database at ' . $this->path() . ' and none could be fetched', $locator->warnings()[0]);
        self::assertStringContainsString('HTTP 500', $locator->warnings()[0]);
    }

    public function testAMaximumAgeTurnsAnOldUnconfirmedCopyIntoAFailure(): void
    {
        $bytes = self::database('h1', self::hoursAgo(72));
        mkdir(dirname($this->path()), 0700, true);
        file_put_contents($this->path(), $bytes);
        $locator = new DatabaseLocator($this->composer(), $this->downloader([]));

        self::assertSame(Freshness::Unconfirmed, $locator->locate($this->settings($locator, self::URL, '4d'))?->freshness, 'within the limit: used with a warning');

        $strict = new DatabaseLocator($this->composer(), $this->downloader([]));
        try {
            $strict->locate($this->settings($strict, self::URL, '24'));
            self::fail('expected the old copy to be refused');
        } catch (AdvisoryLookupFailed $e) {
            self::assertStringContainsString('built 3 days ago, older than the allowed 24 hours', $e->getMessage());
        }
    }

    public function testOfflineUsesTheCopyWithoutAnyRequestAndWarns(): void
    {
        $bytes = self::database('h1', self::hoursAgo(3));
        mkdir(dirname($this->path()), 0700, true);
        file_put_contents($this->path(), $bytes);
        $locator = new DatabaseLocator($this->composer(), $this->downloader([], $requests), true);

        $located = $locator->locate($this->settings($locator));

        self::assertSame(Freshness::Offline, $located?->freshness);
        self::assertSame([], $requests);
        self::assertStringContainsString('Offline: using the advisory database at', $locator->warnings()[0]);

        $empty = new DatabaseLocator($this->composer(), $this->downloader([]), true);
        @unlink($this->path());
        self::assertNull($empty->locate($this->settings($empty)));
        self::assertStringContainsString('Offline mode and no advisory database at', $empty->warnings()[0]);
    }

    public function testAMismatchedDigestIsFatalAndLeavesNoFile(): void
    {
        $bytes = self::database('h1', self::hoursAgo(1));
        $locator = new DatabaseLocator($this->composer(), $this->downloader([self::URL => 'tampered', self::URL . '.sha256' => str_repeat('0', 64)] + [self::LATEST => json_encode(['sha256' => hash('sha256', $bytes)], JSON_THROW_ON_ERROR)]));
        try {
            $locator->locate($this->settings($locator));
            self::fail('expected a checksum failure');
        } catch (AdvisoryLookupFailed $e) {
            self::assertStringContainsString('does not match its published sha256', $e->getMessage());
        }
        self::assertFileDoesNotExist($this->path());
    }

    public function testAPublisherMovingBetweenTheTwoRequestsIsResolvedThroughTheSidecar(): void
    {
        $bytes = self::database('h2', self::hoursAgo(0));
        $stale = json_encode(['sha256' => str_repeat('a', 64), 'dataset_hash' => 'h1'], JSON_THROW_ON_ERROR); // latest.json from before the move
        $locator = new DatabaseLocator($this->composer(), $this->downloader([self::LATEST => $stale, self::URL => $bytes, self::URL . '.sha256' => hash('sha256', $bytes)]));

        self::assertSame(Freshness::Downloaded, $locator->locate($this->settings($locator))?->freshness);
        self::assertStringEqualsFile($this->path(), $bytes);
    }

    public function testADownloadWithoutAnyPublishedDigestIsNotAttemptedByDefault(): void
    {
        $bytes = self::database('h1', self::hoursAgo(1));
        $locator = new DatabaseLocator($this->composer(), $this->downloader([self::URL => $bytes], $requests));

        self::assertNull($locator->locate($this->settings($locator)));
        self::assertNotContains(self::URL, $requests);
        self::assertStringContainsString('no latest.json or .sha256 published there; pass --allow-unverified-database', $locator->warnings()[0]);
    }

    public function testAnUnverifiedDownloadWarnsNowAndOnEveryLaterUseWhenExplicitlyAllowed(): void
    {
        $bytes = self::database('h1', self::hoursAgo(1));
        $locator = new DatabaseLocator($this->composer(), $this->downloader([self::URL => $bytes]), false, false);

        $located = $locator->locate($this->settings($locator));

        self::assertSame(Freshness::Downloaded, $located?->freshness);
        self::assertStringEqualsFile($this->path(), $bytes);
        self::assertCount(1, $locator->warnings());
        self::assertStringContainsString('was not verified against a sha256', $locator->warnings()[0]);

        $again = new DatabaseLocator($this->composer(), $this->downloader([]), false, false);
        self::assertSame(Freshness::Unconfirmed, $again->locate($this->settings($again))?->freshness);
        $warnings = implode("\n", $again->warnings());
        self::assertStringContainsString('downloaded without a published sha256 to verify against', $warnings, 'the disclosure belongs to the bytes in use');
    }

    public function testAnExpectedDigestIsTheTrustAnchorAndIsCheckedOnEveryUse(): void
    {
        $bytes = self::database('h1', self::hoursAgo(1));
        $pin = hash('sha256', $bytes);
        // No sidecar, no latest.json: the pin alone verifies the download... once the publisher can be reached at all.
        $locator = new DatabaseLocator($this->composer(), $this->downloader([self::URL => $bytes, self::URL . '.sha256' => str_repeat('f', 64)]), false, true, $pin);
        self::assertSame(Freshness::Downloaded, $locator->locate($this->settings($locator))?->freshness, 'the pin outranks a sidecar that disagrees');
        self::assertSame([], $locator->warnings());

        file_put_contents($this->path(), self::database('h9', self::hoursAgo(0)));
        $tampered = new DatabaseLocator($this->composer(), $this->downloader(self::published($bytes, 'h1', self::hoursAgo(1))), false, true, $pin);
        try {
            $tampered->locate($this->settings($tampered));
            self::fail('a local copy that differs from the pin must be refused');
        } catch (AdvisoryLookupFailed $e) {
            self::assertStringContainsString('does not match the expected sha256', $e->getMessage());
            self::assertStringContainsString('the copy was discarded', $e->getMessage());
        }
        self::assertFileDoesNotExist($this->path());
    }

    public function testOnlyHttpsSourcesAreContacted(): void
    {
        $locator = new DatabaseLocator($this->composer(), $this->downloader([]));
        try {
            $locator->locate($this->settings($locator, 'http://example.test/advisories.sqlite'));
            self::fail('plain http must be refused');
        } catch (AdvisoryLookupFailed $e) {
            self::assertStringContainsString('only https:// URLs are downloaded', $e->getMessage());
        }
    }

    public function testASymbolicLinkAtThePathIsRefused(): void
    {
        mkdir(dirname($this->path()), 0700, true);
        symlink('/etc/hostname', $this->path());
        $locator = new DatabaseLocator($this->composer(), $this->downloader([]));
        try {
            $locator->locate($this->settings($locator));
            self::fail('a symlink at the database path must be refused');
        } catch (AdvisoryLookupFailed $e) {
            self::assertStringContainsString('is a symbolic link', $e->getMessage());
        }
    }

    public function testCredentialsInTheSourceUrlNeverReachMessages(): void
    {
        $url = 'https://user:s3cret@example.test/db/advisories.sqlite';
        $locator = new DatabaseLocator($this->composer(), $this->downloader([]));
        self::assertNull($locator->locate($this->settings($locator, $url)));
        self::assertStringContainsString('https://***@example.test', $locator->warnings()[0]);
        self::assertStringNotContainsString('s3cret', $locator->warnings()[0]);
        self::assertSame('see https://***@h/x and https://***@h/y', DatabaseLocator::redact('see https://a:b@h/x and https://c@h/y'));
    }

    public function testAFileThatIsNotADatabaseIsReplaced(): void
    {
        mkdir(dirname($this->path()), 0700, true);
        file_put_contents($this->path(), 'not sqlite');
        $bytes = self::database('h1', self::hoursAgo(1));
        $locator = new DatabaseLocator($this->composer(), $this->downloader([self::URL => $bytes] + self::published($bytes, 'h1', self::hoursAgo(1))));

        self::assertSame(Freshness::Downloaded, $locator->locate($this->settings($locator))?->freshness);
        self::assertStringEqualsFile($this->path(), $bytes);
        self::assertStringContainsString('is not a readable advisory database', $locator->warnings()[0]);
    }

    public function testSourcesAreTriedInOrderUntilOneAnswers(): void
    {
        $bytes = self::database('h1', self::hoursAgo(1));
        $mirror = 'https://mirror.test/advisories.sqlite';
        $locator = new DatabaseLocator($this->composer(), $this->downloader([$mirror => $bytes, $mirror . '.sha256' => hash('sha256', $bytes)], $requests));

        $located = $locator->locate($this->settings($locator, self::URL . ',' . $mirror));

        self::assertSame(Freshness::Downloaded, $located?->freshness);
        self::assertStringContainsString('downloaded from ' . $mirror, $located->provenance);
        self::assertSame([self::LATEST, self::URL . '.sha256', 'https://mirror.test/latest.json', $mirror . '.sha256', $mirror], $requests);
        self::assertSame([], $locator->warnings(), 'a source that is skipped over is not a warning when a later one answers');
    }

    public function testARebuildCallbackReplacesTheDownloadWhenTheCopyIsStale(): void
    {
        $stale = self::database('h0', self::hoursAgo(48));
        $published = self::database('h1', self::hoursAgo(1));
        mkdir(dirname($this->path()), 0700, true);
        file_put_contents($this->path(), $stale);
        $locator = new DatabaseLocator($this->composer(), $this->downloader(self::published($published, 'h1', self::hoursAgo(1)), $requests));
        $rebuilt = self::database('h1', self::hoursAgo(0));

        $located = $locator->locate($this->settings($locator), static function (string $path) use ($rebuilt): void {
            file_put_contents($path, $rebuilt);
        });

        self::assertSame(Freshness::Rebuilt, $located?->freshness);
        self::assertStringEqualsFile($this->path(), $rebuilt);
        self::assertNotContains(self::URL, $requests);

        // Unreachable publisher and no copy: build rather than run without a database.
        @unlink($this->path());
        $isolated = new DatabaseLocator($this->composer(), $this->downloader([]));
        $located = $isolated->locate($this->settings($isolated), static function (string $path) use ($rebuilt): void {
            file_put_contents($path, $rebuilt);
        });
        self::assertSame(Freshness::Rebuilt, $located?->freshness);
        self::assertStringContainsString('unreachable', $located->provenance);
    }

    public function testALocalPathAsTheSourceIsReadAsItIs(): void
    {
        $file = $this->cacheDir . '/own.sqlite';
        file_put_contents($file, self::database('h1', self::hoursAgo(1)));
        $locator = new DatabaseLocator($this->composer(), $this->downloader([], $requests));

        $located = $locator->locate($locator->settings($file));

        self::assertSame(Freshness::Explicit, $located?->freshness);
        self::assertSame(realpath($file), $located->path);
        self::assertSame([], $requests);
        self::assertSame(realpath($file), $locator->resolve($file));
        try {
            $locator->resolve($this->cacheDir . '/missing.sqlite');
            self::fail('a missing explicit file is an error');
        } catch (AdvisoryLookupFailed $e) {
            self::assertStringContainsString('does not exist', $e->getMessage());
        }
        @unlink($file);
    }

    public function testSettingsResolveIndependentlyWithTheirOwnDefaults(): void
    {
        $locator = new DatabaseLocator($this->composer(), $this->downloader([]));

        $sourceOnly = $locator->settings('https://mirror.test/a.sqlite');
        self::assertSame(['https://mirror.test/a.sqlite'], $sourceOnly->sources);
        self::assertStringStartsWith('https://github.com/hexblot/composer-remediate/releases/download/advisory-db-latest/', DatabaseSettings::DEFAULT_SOURCE);
        self::assertSame($this->path(), $sourceOnly->path, 'a source never moves the path');
        self::assertFalse($sourceOnly->pathConfigured);
        self::assertTrue($sourceOnly->sourcesConfigured);

        $pathOnly = $locator->settings(null, '/srv/db.sqlite');
        self::assertSame('/srv/db.sqlite', $pathOnly->path);
        self::assertTrue($pathOnly->pathConfigured);
        // The test bootstrap sets REMEDIATE_DATABASE=composer so that no test reaches GitHub; that is
        // what an unconfigured source resolves to here, and it is reported as such.
        self::assertFalse($pathOnly->usesDatabase());
        self::assertTrue($pathOnly->sourcesConfigured);

        self::assertFalse($locator->settings('none')->usesDatabase());
        self::assertFalse($locator->settings(null, null, null, true)->usesDatabase(), '--no-database');
        self::assertSame(['https://a.test/x.sqlite', 'https://b.test/y.sqlite'], $locator->settings(' https://a.test/x.sqlite, https://b.test/y.sqlite ')->sources);

        self::assertSame(2 * 86400, $locator->settings(self::URL, null, '2d')->maxAgeSeconds);
        self::assertSame(36 * 3600, $locator->settings(self::URL, null, '36h')->maxAgeSeconds);
        self::assertSame(24 * 3600, $locator->settings(self::URL, null, '24')->maxAgeSeconds);
        self::assertNull($locator->settings(self::URL)->maxAgeSeconds);
        $this->expectException(\InvalidArgumentException::class);
        $locator->settings(self::URL, null, 'soon');
    }

    public function testComposerJsonProvidesEverySettingIncludingASourceList(): void
    {
        $composer = $this->composer(['remediate' => ['database' => ['https://a.test/x.sqlite', 'https://b.test/y.sqlite'], 'database_path' => '/srv/adv.sqlite', 'database_max_age' => '48h']]);
        $locator = new DatabaseLocator($composer, $this->downloader([]));

        // The environment outranks composer.json; the test bootstrap sets it, so it is lifted here.
        $env = \Composer\Util\Platform::getEnv(DatabaseSettings::ENV_LOCATION);
        \Composer\Util\Platform::clearEnv(DatabaseSettings::ENV_LOCATION);
        try {
            $settings = $locator->settings();
            self::assertSame(['https://a.test/x.sqlite', 'https://b.test/y.sqlite'], $settings->sources);
            self::assertSame('/srv/adv.sqlite', $settings->path);
            self::assertSame(48 * 3600, $settings->maxAgeSeconds);
            self::assertSame('https://a.test/x.sqlite,https://b.test/y.sqlite', $locator->configured(null));
            self::assertSame('https://c.test/z.sqlite', $locator->configured('https://c.test/z.sqlite'), 'the option wins');

            $bare = new DatabaseLocator($this->composer(), $this->downloader([]));
            self::assertSame([DatabaseSettings::DEFAULT_SOURCE], $bare->settings()->sources, 'nothing configured anywhere: the published database');
            self::assertFalse($bare->settings()->sourcesConfigured);
        } finally {
            if (is_string($env)) {
                \Composer\Util\Platform::putEnv(DatabaseSettings::ENV_LOCATION, $env);
            }
        }
    }
}
