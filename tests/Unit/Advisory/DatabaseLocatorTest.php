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
        foreach (glob($this->cacheDir . '/remediate/sources/*') ?: [] as $file) {
            @unlink($file);
        }
        @rmdir($this->cacheDir . '/remediate/sources');
        @rmdir($this->cacheDir . '/remediate');
        @rmdir($this->cacheDir . '/var');
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
    /** @param list<string> $sourceNames the build's source names as db-build records them (`local:<file>` for --include files) */
    private static function database(string $datasetHash, string $builtAt, array $sourceNames = ['Packagist']): string
    {
        $tmp = tempnam(sys_get_temp_dir(), 'remediate-db-');
        self::assertNotFalse($tmp);
        @unlink($tmp);
        $pdo = new \PDO('sqlite:' . $tmp, null, null, [\PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION]);
        $pdo->exec('CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)');
        $insert = $pdo->prepare('INSERT INTO meta VALUES (?, ?)');
        $sources = json_encode(array_map(static fn (string $n): array => ['name' => $n, 'fetched_at' => $builtAt, 'records' => 1], $sourceNames), JSON_THROW_ON_ERROR);
        foreach (['schema_version' => '1', 'built_at' => $builtAt, 'dataset_hash' => $datasetHash, 'advisory_count' => '1', 'sources' => $sources] as $k => $v) {
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

    public function testAFileThatIsNotADatabaseIsNeverReplaced(): void
    {
        // The path may have been pointed at something that matters; this tool does not overwrite what it did not write.
        mkdir(dirname($this->path()), 0700, true);
        file_put_contents($this->path(), 'not sqlite');
        $bytes = self::database('h1', self::hoursAgo(1));
        $locator = new DatabaseLocator($this->composer(), $this->downloader([self::URL => $bytes] + self::published($bytes, 'h1', self::hoursAgo(1)), $requests));
        try {
            $locator->locate($this->settings($locator));
            self::fail('a foreign file at the path must be refused');
        } catch (AdvisoryLookupFailed $e) {
            self::assertStringContainsString('is not an advisory database', $e->getMessage());
            self::assertStringContainsString('is not replaced', $e->getMessage());
        }
        self::assertStringEqualsFile($this->path(), 'not sqlite');
        self::assertSame([], $requests, 'nothing is even fetched');
    }

    public function testADownloadThatIsNotADatabaseNeverReachesThePath(): void
    {
        // A source (or a project's composer.json pointing at one) cannot use the tool to write arbitrary bytes.
        $payload = "<?php system('id');";
        $locator = new DatabaseLocator($this->composer(), $this->downloader([self::URL => $payload, self::LATEST => json_encode(['sha256' => hash('sha256', $payload)], JSON_THROW_ON_ERROR)]));
        try {
            $locator->locate($this->settings($locator));
            self::fail('non-database content must be refused even with a matching digest');
        } catch (AdvisoryLookupFailed $e) {
            self::assertStringContainsString('is not an advisory database', $e->getMessage());
            self::assertStringContainsString('nothing was written to ' . $this->path(), $e->getMessage());
        }
        self::assertFileDoesNotExist($this->path());
        self::assertSame([], glob(dirname($this->path()) . '/*.tmp-*') ?: []);
    }

    public function testACopyDownloadedFromOneSourceIsNeverCurrentForAnother(): void
    {
        // Source A publishes an (empty) database; the copy must not pass as current when the source
        // becomes B, whatever its build time says, so B's data is fetched.
        $fromA = self::database('empty', self::hoursAgo(0));
        $locator = new DatabaseLocator($this->composer(), $this->downloader([self::URL => $fromA] + self::published($fromA, 'empty', self::hoursAgo(0))));
        self::assertSame(Freshness::Downloaded, $locator->locate($this->settings($locator))?->freshness);

        $b = 'https://other.test/advisories.sqlite';
        $fromB = self::database('real', self::hoursAgo(5));
        $switched = new DatabaseLocator($this->composer(), $this->downloader([$b => $fromB, $b . '.sha256' => hash('sha256', $fromB), 'https://other.test/latest.json' => json_encode(['sha256' => hash('sha256', $fromB), 'dataset_hash' => 'real', 'published_at' => self::hoursAgo(5)], JSON_THROW_ON_ERROR)]));
        $located = $switched->locate($this->settings($switched, $b));

        self::assertSame(Freshness::Downloaded, $located?->freshness);
        self::assertStringEqualsFile($this->path(), $fromB);
    }

    public function testALocalBuildClaimingToComeFromTheFutureIsNotCurrent(): void
    {
        $local = self::database('planted', gmdate(DATE_ATOM, time() + 30 * 86400));
        $published = self::database('h1', self::hoursAgo(1));
        mkdir(dirname($this->path()), 0700, true);
        file_put_contents($this->path(), $local);
        $locator = new DatabaseLocator($this->composer(), $this->downloader([self::URL => $published] + self::published($published, 'h1', self::hoursAgo(1))));

        self::assertSame(Freshness::Downloaded, $locator->locate($this->settings($locator))?->freshness);
        self::assertStringEqualsFile($this->path(), $published);
    }

    public function testAPinnedDigestAppliesToAFileNamedAsTheSource(): void
    {
        $file = $this->cacheDir . '/own.sqlite';
        $bytes = self::database('h1', self::hoursAgo(1));
        file_put_contents($file, $bytes);
        $good = new DatabaseLocator($this->composer(), $this->downloader([]), false, true, hash('sha256', $bytes));
        self::assertSame(Freshness::Explicit, $good->locate($good->settings($file))?->freshness);

        $bad = new DatabaseLocator($this->composer(), $this->downloader([]), false, true, str_repeat('b', 64));
        try {
            $bad->locate($bad->settings($file));
            self::fail('a pinned digest must constrain every path that selects a database');
        } catch (AdvisoryLookupFailed $e) {
            self::assertStringContainsString('does not match the expected sha256', $e->getMessage());
        }
        self::assertFileExists($file, 'a file the operator named is not discarded');
        @unlink($file);
    }

    public function testALocalBuildWithPrivateAdvisoriesIsKeptRatherThanReplaced(): void
    {
        $private = self::database('mine', self::hoursAgo(30), ['Packagist', 'local:internal.json']);
        $published = self::database('h1', self::hoursAgo(1));
        mkdir(dirname($this->path()), 0700, true);
        file_put_contents($this->path(), $private);
        $responses = [self::URL => $published] + self::published($published, 'h1', self::hoursAgo(1));

        $locator = new DatabaseLocator($this->composer(), $this->downloader($responses, $requests));
        $located = $locator->locate($this->settings($locator));
        self::assertSame(Freshness::Unconfirmed, $located?->freshness);
        self::assertStringContainsString('local build with private advisories, kept', $located->provenance);
        self::assertStringEqualsFile($this->path(), $private);
        self::assertNotContains(self::URL, $requests);
        self::assertStringContainsString('private advisories (internal.json)', $locator->warnings()[0]);
        self::assertStringContainsString('public advisories published since it was built 30 hours ago are unknown', $locator->warnings()[0]);
        self::assertStringContainsString('remediate:db-build --if-stale and the same --include files', $locator->warnings()[0]);

        // --rebuild-database builds with the defaults, which would drop the private advisories: kept too.
        $defaults = new DatabaseLocator($this->composer(), $this->downloader($responses));
        $rebuilt = false;
        self::assertSame(Freshness::Unconfirmed, $defaults->locate($this->settings($defaults), static function () use (&$rebuilt): void {
            $rebuilt = true;
        })?->freshness);
        self::assertFalse($rebuilt);

        // db-build --if-stale with the same --include files is the refresh that keeps them.
        $complete = new DatabaseLocator($this->composer(), $this->downloader($responses));
        $refreshed = self::database('mine2', self::hoursAgo(0), ['Packagist', 'local:internal.json']);
        self::assertSame(Freshness::Rebuilt, $complete->locate($this->settings($complete), static function (string $path) use ($refreshed): void {
            file_put_contents($path, $refreshed);
        }, true)?->freshness);
        self::assertStringEqualsFile($this->path(), $refreshed);
    }

    public function testContentAtAProjectChosenPathCountsOnlyWhenItMatchesThePublisher(): void
    {
        // A checked-in empty database with a recent build time, at a path the project's composer.json names.
        $project = $this->cacheDir . '/project';
        mkdir($project . '/var', 0700, true);
        $planted = self::database('empty', self::hoursAgo(0));
        file_put_contents($project . '/var/adv.sqlite', $planted);
        $published = self::database('real', self::hoursAgo(5));
        $responses = [self::URL => $published] + self::published($published, 'real', self::hoursAgo(5));
        $composer = $this->composer(['remediate' => ['database_path' => 'var/adv.sqlite']]);

        $locator = new DatabaseLocator($composer, $this->downloader($responses));
        $settings = $locator->settings(self::URL, null, null, false, $project);
        self::assertTrue($settings->pathFromProject);
        $located = $locator->locate($settings);
        self::assertSame(Freshness::Downloaded, $located?->freshness, 'the planted file is not a newer local build; the publisher\'s data replaces it');
        self::assertStringEqualsFile($project . '/var/adv.sqlite', $published);

        // The same planted file with the trusted publisher's dataset hash copied into its metadata: still replaced.
        file_put_contents($project . '/var/adv.sqlite', self::database('real', self::hoursAgo(0)));
        $again = new DatabaseLocator($composer, $this->downloader($responses));
        self::assertSame(Freshness::Downloaded, $again->locate($again->settings(self::URL, null, null, false, $project))?->freshness);

        // Publisher unreachable: content at a project path is not the fallback either.
        file_put_contents($project . '/var/adv.sqlite', $planted);
        $outage = new DatabaseLocator($composer, $this->downloader([]));
        self::assertNull($outage->locate($outage->settings(self::URL, null, null, false, $project)));
        self::assertStringContainsString('a path chosen by the analysed project) cannot be confirmed against its source and is not used', implode("\n", $outage->warnings()));

        // Only bytes identical to the published database pass.
        file_put_contents($project . '/var/adv.sqlite', $published);
        $same = new DatabaseLocator($composer, $this->downloader($responses));
        self::assertSame(Freshness::Confirmed, $same->locate($same->settings(self::URL, null, null, false, $project))?->freshness);
        @unlink($project . '/var/adv.sqlite');
        @unlink($project . '/var/adv.sqlite.status.json');
        @rmdir($project . '/var');
        @rmdir($project);
    }

    public function testAForgedDatasetHashDoesNotSurviveASourceSwitch(): void
    {
        // Untrusted publisher A serves an empty database whose metadata copies trusted publisher B's dataset hash.
        $forged = self::database('trusted-hash', self::hoursAgo(0));
        $a = new DatabaseLocator($this->composer(), $this->downloader([self::URL => $forged] + self::published($forged, 'trusted-hash', self::hoursAgo(0))));
        self::assertSame(Freshness::Downloaded, $a->locate($this->settings($a))?->freshness);

        $b = 'https://trusted.test/advisories.sqlite';
        $real = self::database('trusted-hash', self::hoursAgo(3));
        $switched = new DatabaseLocator($this->composer(), $this->downloader([$b => $real, $b . '.sha256' => hash('sha256', $real), 'https://trusted.test/latest.json' => json_encode(['sha256' => hash('sha256', $real), 'dataset_hash' => 'trusted-hash', 'published_at' => self::hoursAgo(3)], JSON_THROW_ON_ERROR)]));
        self::assertSame(Freshness::Downloaded, $switched->locate($this->settings($switched, $b))?->freshness, 'the dataset hash is A\'s claim, not proof about B');
        self::assertStringEqualsFile($this->path(), $real);

        // And when B cannot be reached, A's copy is not the fallback.
        file_put_contents($this->path(), $forged);
        file_put_contents($this->path() . '.status.json', json_encode(['verified' => true, 'url' => self::URL, 'fetched_at' => gmdate(DATE_ATOM)], JSON_THROW_ON_ERROR));
        $outage = new DatabaseLocator($this->composer(), $this->downloader([]));
        self::assertNull($outage->locate($this->settings($outage, $b)));
        self::assertStringContainsString('was downloaded from ' . self::URL . ', which is not among the configured sources, and is not used', implode("\n", $outage->warnings()));
    }

    public function testABuildOverADownloadedCopyIsALocalBuild(): void
    {
        $downloaded = self::database('h1', self::hoursAgo(2));
        $first = new DatabaseLocator($this->composer(), $this->downloader([self::URL => $downloaded] + self::published($downloaded, 'h1', self::hoursAgo(2))));
        self::assertSame(Freshness::Downloaded, $first->locate($this->settings($first))?->freshness);
        self::assertFileExists($this->path() . '.status.json');

        // The writer retires the status file; the locator also ignores a status record older than the
        // database beside it (a rebuild is always newer than the download it replaced). Sequence:
        // downloaded two hours ago, rebuilt with a private file one hour ago, publisher moved on just now.
        file_put_contents($this->path() . '.status.json', json_encode(['verified' => true, 'url' => self::URL, 'fetched_at' => self::hoursAgo(2)], JSON_THROW_ON_ERROR));
        $rebuilt = self::database('mine', self::hoursAgo(1), ['Packagist', 'local:internal.json']);
        file_put_contents($this->path(), $rebuilt); // an in-place rebuild that left the status file behind
        $newer = self::database('h2', self::hoursAgo(0));
        $locator = new DatabaseLocator($this->composer(), $this->downloader([self::URL => $newer] + self::published($newer, 'h2', self::hoursAgo(0))));

        $located = $locator->locate($this->settings($locator));

        self::assertSame(Freshness::Unconfirmed, $located?->freshness, 'a local build with private advisories, kept');
        self::assertStringEqualsFile($this->path(), $rebuilt);
        self::assertStringContainsString('private advisories (internal.json)', implode("\n", $locator->warnings()));
    }

    public function testAPinnedDigestDownloadsEvenWhenThePublisherOffersNoDigest(): void
    {
        $bytes = self::database('h1', self::hoursAgo(1));
        $locator = new DatabaseLocator($this->composer(), $this->downloader([self::URL => $bytes]), false, true, hash('sha256', $bytes));

        $located = $locator->locate($this->settings($locator));

        self::assertSame(Freshness::Downloaded, $located?->freshness);
        self::assertStringContainsString('verified against the pinned digest', $located->provenance);
        self::assertSame([], $locator->warnings());
    }

    public function testAProjectChosenSourceGetsItsOwnFileAndIsReported(): void
    {
        $env = \Composer\Util\Platform::getEnv(DatabaseSettings::ENV_LOCATION);
        \Composer\Util\Platform::clearEnv(DatabaseSettings::ENV_LOCATION);
        try {
            $composer = $this->composer(['remediate' => ['database' => 'https://evil.test/advisories.sqlite']]);
            $locator = new DatabaseLocator($composer, $this->downloader([]));
            $settings = $locator->settings();

            self::assertSame(['https://evil.test/advisories.sqlite'], $settings->sources);
            self::assertTrue($settings->sourcesFromProject);
            self::assertNotSame($this->path(), $settings->path, 'never the shared default file');
            self::assertStringStartsWith($this->cacheDir . '/remediate/sources/', $settings->path);
            self::assertCount(1, $settings->notes);
            self::assertStringContainsString("chosen by the analysed project's composer.json", $settings->notes[0]);

            $withCredentials = new DatabaseLocator($this->composer(['remediate' => ['database' => 'https://user:s3cret@evil.test/advisories.sqlite']]), $this->downloader([]));
            self::assertStringContainsString('https://***@evil.test', $withCredentials->settings()->notes[0]);
            self::assertStringNotContainsString('s3cret', $withCredentials->settings()->notes[0]);

            $locator->locate($settings);
            self::assertStringContainsString("chosen by the analysed project's composer.json", $locator->warnings()[0], 'the note reaches the report');

            $operator = $locator->settings('https://mirror.test/x.sqlite');
            self::assertSame($this->path(), $operator->path, 'an operator-chosen source uses the default path');
            self::assertFalse($operator->sourcesFromProject);
        } finally {
            if (is_string($env)) {
                \Composer\Util\Platform::putEnv(DatabaseSettings::ENV_LOCATION, $env);
            }
        }
    }

    public function testAProjectChosenPathMustStayInsideTheProject(): void
    {
        $project = $this->cacheDir . '/project';
        mkdir($project . '/sub', 0700, true);
        $outside = $this->cacheDir . '/outside';
        mkdir($outside, 0700, true);
        symlink($outside, $project . '/escape');
        $downloader = $this->downloader([]);

        $fine = new DatabaseLocator($this->composer(['remediate' => ['database_path' => 'sub/adv.sqlite']]), $downloader);
        self::assertSame(realpath($project . '/sub') . '/adv.sqlite', $fine->settings(self::URL, null, null, false, $project)->path);
        $deep = new DatabaseLocator($this->composer(['remediate' => ['database_path' => 'new/dirs/adv.sqlite']]), $downloader);
        self::assertSame(realpath($project) . '/new/dirs/adv.sqlite', $deep->settings(self::URL, null, null, false, $project)->path);
        self::assertDirectoryDoesNotExist($project . '/new', 'resolving a setting creates nothing');

        foreach (['/etc/passwd', '../elsewhere.sqlite', 'sub/../../x.sqlite', 'escape/adv.sqlite', 'escape/deeper/adv.sqlite'] as $bad) {
            $locator = new DatabaseLocator($this->composer(['remediate' => ['database_path' => $bad]]), $downloader);
            try {
                $locator->settings(self::URL, null, null, false, $project);
                self::fail("$bad must be rejected");
            } catch (\InvalidArgumentException $e) {
                self::assertStringContainsString('extra.remediate.database_path', $e->getMessage(), $bad);
            }
        }
        self::assertDirectoryDoesNotExist($outside . '/deeper', 'nothing was created through the link before the rejection');
        $operator = new DatabaseLocator($this->composer(['remediate' => ['database_path' => '/etc/passwd']]), $downloader);
        self::assertSame('/tmp/operator.sqlite', $operator->settings(self::URL, '/tmp/operator.sqlite', null, false, $project)->path, 'the operator\'s own path outranks and is unrestricted');
        @unlink($project . '/escape');
        @rmdir($project . '/sub');
        @rmdir($project);
        @rmdir($outside);
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
        $composer = $this->composer(['remediate' => ['database' => ['https://a.test/x.sqlite', 'https://b.test/y.sqlite'], 'database_path' => 'var/adv.sqlite', 'database_max_age' => '48h']]);
        $locator = new DatabaseLocator($composer, $this->downloader([]));

        // The environment outranks composer.json; the test bootstrap sets it, so it is lifted here.
        $env = \Composer\Util\Platform::getEnv(DatabaseSettings::ENV_LOCATION);
        \Composer\Util\Platform::clearEnv(DatabaseSettings::ENV_LOCATION);
        try {
            $settings = $locator->settings(null, null, null, false, $this->cacheDir);
            self::assertSame(['https://a.test/x.sqlite', 'https://b.test/y.sqlite'], $settings->sources);
            self::assertSame(realpath($this->cacheDir) . '/var/adv.sqlite', $settings->path, 'a project path, relative and inside the project');
            self::assertTrue($settings->sourcesFromProject);
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
