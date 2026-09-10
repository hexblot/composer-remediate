<?php

declare(strict_types=1);

namespace Remediate\Tests\Unit\Advisory\Source;

use Composer\Semver\Constraint\Constraint;
use Composer\Semver\VersionParser;
use PHPUnit\Framework\TestCase;
use Remediate\Engine\Advisory\Db\NormalizedAdvisory;
use Remediate\Engine\Advisory\Db\Source\OsvDumpSource;
use Remediate\Tests\Support\ScriptedDownloader;
use Remediate\Tests\Support\Zips;

/**
 * The OSV Packagist dump: one JSON document per entry. Records about Packagist packages the build
 * cannot read become coverage gaps; documents about other ecosystems are simply not ours.
 */
final class OsvDumpSourceTest extends TestCase
{
    private string $tempDir;

    protected function setUp(): void
    {
        $this->tempDir = sys_get_temp_dir() . '/composer-remediate-osv-' . bin2hex(random_bytes(4));
    }

    protected function tearDown(): void
    {
        foreach (glob($this->tempDir . '/*') ?: [] as $file) {
            @unlink($file);
        }
        @rmdir($this->tempDir);
    }

    /** @return array<string, string> entry name => contents */
    private static function dump(): array
    {
        $json = static fn (array $doc): string => json_encode($doc, JSON_THROW_ON_ERROR);

        return [
            'README.md' => 'not a document',
            'GHSA-aaaa-bbbb-cccc.json' => $json([
                'id' => 'GHSA-aaaa-bbbb-cccc',
                'aliases' => ['CVE-2026-10001', ''],
                'summary' => 'Synthetic XSS in acme/lib',
                'published' => '2026-01-10T00:00:00Z',
                'modified' => '2026-02-01T12:00:00Z',
                'references' => [
                    ['type' => 'WEB', 'url' => 'https://example.invalid/web'],
                    ['type' => 'ADVISORY', 'url' => 'https://example.invalid/advisory'],
                ],
                'database_specific' => ['severity' => 'MODERATE'],
                'affected' => [
                    ['package' => ['ecosystem' => 'Packagist', 'name' => 'Acme/Lib'], 'ranges' => [['type' => 'ECOSYSTEM', 'events' => [['introduced' => '1.0.0'], ['fixed' => '1.2.0']]]]],
                    ['package' => ['ecosystem' => 'Packagist', 'name' => 'acme/other'], 'ranges' => [['type' => 'ECOSYSTEM', 'events' => [['introduced' => '0'], ['fixed' => '2.0.0']]]]],
                    ['package' => ['ecosystem' => 'npm', 'name' => 'left-pad'], 'ranges' => [['type' => 'SEMVER', 'events' => [['introduced' => '0'], ['fixed' => '1.0.0']]]]],
                    'not an entry',
                ],
            ]),
            'GHSA-npm-only.json' => $json([
                'id' => 'GHSA-npm-only',
                'affected' => [['package' => ['ecosystem' => 'npm', 'name' => 'left-pad'], 'ranges' => [['type' => 'SEMVER', 'events' => [['introduced' => '0'], ['fixed' => '1.0.0']]]]]],
            ]),
            'GHSA-bad-version.json' => $json([
                'id' => 'GHSA-bad-version',
                'affected' => [['package' => ['ecosystem' => 'Packagist', 'name' => 'acme/unreadable'], 'ranges' => [['type' => 'ECOSYSTEM', 'events' => [['introduced' => 'not a version']]]]]],
            ]),
            'broken.json' => '{not json',
            'noid.json' => $json(['summary' => 'a document without an id']),
            'GHSA-withdrawn.json' => $json([
                'id' => 'GHSA-withdrawn',
                'published' => '2025-12-01T00:00:00Z',
                'withdrawn' => '2026-01-05T00:00:00Z',
                'affected' => [['package' => ['ecosystem' => 'packagist', 'name' => 'acme/gone'], 'versions' => ['3.0.0']]],
            ]),
        ];
    }

    private static function affects(string $expression, string $version): bool
    {
        $parser = new VersionParser();

        return $parser->parseConstraints($expression)->matches(new Constraint('==', $parser->normalize($version)));
    }

    public function testReadsRecordsAndReportsTheRestAsGaps(): void
    {
        $downloader = new ScriptedDownloader([OsvDumpSource::URL => Zips::build(self::dump())]);
        $source = new OsvDumpSource($downloader, $this->tempDir);
        $log = [];
        $records = $source->fetch(static function (string $line) use (&$log): void {
            $log[] = $line;
        });

        self::assertSame('OSV', $source->name());
        self::assertSame([OsvDumpSource::URL], $downloader->requested());
        self::assertCount(2, $records);
        self::assertSame([
            'OSV: downloading the Packagist ecosystem archive…',
            'OSV: 6 documents, 2 records, skipped: 2 invalid JSON, 1 no Packagist package, 1 no usable range (Packagist records recorded as coverage gaps)',
        ], $log);

        $ghsa = $records[0];
        self::assertSame('CVE-2026-10001', $ghsa->canonicalId, 'the CVE alias outranks the GHSA id');
        self::assertSame(['CVE-2026-10001', 'GHSA-aaaa-bbbb-cccc'], $ghsa->aliases);
        self::assertSame('Synthetic XSS in acme/lib', $ghsa->title);
        self::assertSame('https://example.invalid/advisory', $ghsa->link, 'the ADVISORY reference wins over the osv.dev page');
        self::assertSame('medium', $ghsa->severity, 'OSV "MODERATE" is Composer "medium"');
        self::assertSame('2026-01-10T00:00:00+00:00', $ghsa->reportedAt?->format(DATE_ATOM));
        self::assertNull($ghsa->withdrawnAt);
        self::assertSame(['acme/lib', 'acme/other'], $ghsa->packages(), 'the npm entry is not a Packagist package; names are lower-cased');
        self::assertTrue(self::affects($ghsa->affected[0]->constraint, '1.1.0'));
        self::assertFalse(self::affects($ghsa->affected[0]->constraint, '1.2.0'));
        self::assertSame('OSV', $ghsa->affected[0]->source);
        self::assertTrue(self::affects($ghsa->affected[1]->constraint, '0.1.0'));
        self::assertCount(1, $ghsa->sources);
        self::assertSame('OSV', $ghsa->sources[0]->name);
        self::assertSame('GHSA-aaaa-bbbb-cccc', $ghsa->sources[0]->remoteId);
        self::assertSame('https://osv.dev/vulnerability/GHSA-aaaa-bbbb-cccc', $ghsa->sources[0]->url);
        self::assertSame('2026-02-01T12:00:00+00:00', $ghsa->sources[0]->modifiedAt?->format(DATE_ATOM));

        $withdrawn = $records[1];
        self::assertSame('GHSA-withdrawn', $withdrawn->canonicalId);
        self::assertSame('https://osv.dev/vulnerability/GHSA-withdrawn', $withdrawn->link);
        self::assertNull($withdrawn->severity);
        self::assertNull($withdrawn->title);
        self::assertSame('2026-01-05T00:00:00+00:00', $withdrawn->withdrawnAt?->format(DATE_ATOM));
        self::assertTrue(self::affects($withdrawn->affected[0]->constraint, '3.0.0'), 'an explicit versions list is a range too');
        self::assertFalse(self::affects($withdrawn->affected[0]->constraint, '3.0.1'));

        $gaps = $source->gaps();
        self::assertCount(3, $gaps);
        $byId = [];
        foreach ($gaps as $gap) {
            $byId[$gap->remoteId] = $gap;
        }
        self::assertSame(['GHSA-bad-version', 'broken', 'noid'], array_keys($byId));
        self::assertSame('acme/unreadable', $byId['GHSA-bad-version']->package);
        self::assertSame('no usable range', $byId['GHSA-bad-version']->reason);
        self::assertNull($byId['broken']->package);
        self::assertSame('invalid JSON', $byId['broken']->reason);
        self::assertNull($byId['noid']->package);
        self::assertSame('invalid JSON', $byId['noid']->reason);
        foreach ($gaps as $gap) {
            self::assertSame('OSV', $gap->source);
        }
    }

    public function testAFetchResetsThePreviousGaps(): void
    {
        $downloader = new ScriptedDownloader([OsvDumpSource::URL => Zips::build(['broken.json' => '{'])]);
        $source = new OsvDumpSource($downloader, $this->tempDir);
        self::assertSame([], $source->fetch(static function (): void {}));
        self::assertCount(1, $source->gaps());
        self::assertSame([], $source->fetch(static function (): void {}));
        self::assertCount(1, $source->gaps(), 'gaps describe the last fetch, they do not accumulate');
    }

    public function testACustomUrlIsHonoured(): void
    {
        $url = 'https://mirror.test/packagist/all.zip';
        $downloader = new ScriptedDownloader([$url => Zips::build([])]);
        $records = (new OsvDumpSource($downloader, $this->tempDir, url: $url))->fetch(static function (): void {});
        self::assertSame([], $records);
        self::assertSame([$url], $downloader->requested());
    }

    public function testCanonicalIdPreferenceIsCveThenGhsaThenPksaThenAnythingElse(): void
    {
        self::assertSame([0, 1, 2, 3], array_map([NormalizedAdvisory::class, 'rankId'], ['cve-2026-1', 'GHSA-x', 'PKSA-y', 'OSV-2026-1']));
    }
}
