<?php

declare(strict_types=1);

namespace Remediate\Tests\Unit\Advisory\Source;

use PHPUnit\Framework\TestCase;
use Remediate\Engine\Advisory\Db\Source\FriendsOfPhpSource;
use Remediate\Tests\Support\ScriptedDownloader;
use Remediate\Tests\Support\Zips;

/**
 * FriendsOfPHP/security-advisories read from GitHub's zip of the default branch (the local-checkout
 * route is exercised by the db-build command test).
 */
final class FriendsOfPhpSourceTest extends TestCase
{
    private const LIB = <<<'YAML'
title: Synthetic advisory for acme/lib
link: https://example.invalid/acme-lib
cve: CVE-2026-30001
branches:
    1.x:
        time: 2026-03-01 08:00:00
        versions: ['>=1.0.0', '<1.0.5']
    2.x:
        time: 2026-02-15 08:00:00
        versions: ['>=2.0.0', '<2.0.1']
reference: composer://Acme/Lib
YAML;

    private string $tempDir;

    protected function setUp(): void
    {
        $this->tempDir = sys_get_temp_dir() . '/composer-remediate-fop-' . bin2hex(random_bytes(4));
    }

    protected function tearDown(): void
    {
        foreach (glob($this->tempDir . '/*') ?: [] as $file) {
            @unlink($file);
        }
        @rmdir($this->tempDir);
    }

    public function testReadsTheArchiveAndClassifiesWhatItSkips(): void
    {
        $zip = Zips::build([
            'security-advisories-master/README.md' => 'ignored: not a yaml file',
            'security-advisories-master/acme/lib/CVE-2026-30001.yaml' => self::LIB,
            'security-advisories-master/drupal/core/SA-CORE-2026-001.yaml' => "title: Drupal core\nreference: drupal://core\nbranches: {}\n",
            'security-advisories-master/acme/scalar/X.yaml' => 'just a scalar',
            'security-advisories-master/acme/norange/Y.yaml' => "reference: composer://acme/norange\nbranches:\n    1.x:\n        time: 2026-01-01 00:00:00\n        versions: []\n",
            'security-advisories-master/acme/lib/too/deep/Z.yaml' => self::LIB,
        ]);
        $downloader = new ScriptedDownloader([FriendsOfPhpSource::URL => $zip]);
        $source = new FriendsOfPhpSource($downloader, $this->tempDir);
        $log = [];
        $records = $source->fetch(static function (string $line) use (&$log): void {
            $log[] = $line;
        });

        self::assertSame('FriendsOfPHP', $source->name());
        self::assertSame([FriendsOfPhpSource::URL], $downloader->requested());
        self::assertSame([
            'FriendsOfPHP: downloading the repository archive…',
            'FriendsOfPHP: 4 files, 1 records, 3 skipped (recorded as coverage gaps)',
        ], $log);

        self::assertCount(1, $records);
        $lib = $records[0];
        self::assertSame('CVE-2026-30001', $lib->canonicalId);
        self::assertSame(['CVE-2026-30001', 'acme/lib/CVE-2026-30001.yaml'], $lib->aliases, 'the file name (already the CVE) is not repeated');
        self::assertSame('Synthetic advisory for acme/lib', $lib->title);
        self::assertSame('https://example.invalid/acme-lib', $lib->link);
        self::assertNull($lib->severity, 'FriendsOfPHP files carry no severity');
        self::assertSame('2026-02-15T08:00:00+00:00', $lib->reportedAt?->format(DATE_ATOM), 'the earliest branch time');
        self::assertSame(['acme/lib'], $lib->packages());
        self::assertSame('>=1.0.0,<1.0.5|>=2.0.0,<2.0.1', $lib->affected[0]->constraint);
        self::assertSame('FriendsOfPHP', $lib->affected[0]->source);
        self::assertSame('FriendsOfPHP/security-advisories', $lib->sources[0]->name);
        self::assertSame('acme/lib/CVE-2026-30001.yaml', $lib->sources[0]->remoteId);
        self::assertSame('https://github.com/FriendsOfPHP/security-advisories/blob/master/acme/lib/CVE-2026-30001.yaml', $lib->sources[0]->url);

        $gaps = $source->gaps();
        self::assertCount(2, $gaps, 'the Drupal advisory is not a Composer package and therefore not a gap');
        self::assertSame('acme/scalar/X.yaml', $gaps[0]->remoteId);
        self::assertSame('acme/scalar', $gaps[0]->package, 'the directory names the package even when the file cannot be read');
        self::assertSame('document is not a map', $gaps[0]->reason);
        self::assertSame('acme/norange/Y.yaml', $gaps[1]->remoteId);
        self::assertSame('acme/norange', $gaps[1]->package);
        self::assertSame('no usable version range in branches', $gaps[1]->reason);
        self::assertStringContainsString('"versions":[]', (string) $gaps[1]->raw);
    }

    public function testInvalidYamlIsAGapForThePackageNamedByThePath(): void
    {
        $zip = Zips::build(['security-advisories-master/acme/broken/B.yaml' => "branches: [\n"]);
        $source = new FriendsOfPhpSource(new ScriptedDownloader([FriendsOfPhpSource::URL => $zip]), $this->tempDir);
        self::assertSame([], $source->fetch(static function (): void {}));
        $gaps = $source->gaps();
        self::assertCount(1, $gaps);
        self::assertSame('acme/broken', $gaps[0]->package);
        self::assertSame('invalid YAML', $gaps[0]->reason);
        self::assertNotNull($gaps[0]->raw);
    }

    public function testACustomUrlIsHonoured(): void
    {
        $url = 'https://mirror.test/security-advisories.zip';
        $downloader = new ScriptedDownloader([$url => Zips::build([])]);
        self::assertSame([], (new FriendsOfPhpSource($downloader, $this->tempDir, url: $url))->fetch(static function (): void {}));
        self::assertSame([$url], $downloader->requested());
    }
}
