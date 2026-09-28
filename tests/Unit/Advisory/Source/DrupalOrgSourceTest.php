<?php

declare(strict_types=1);

namespace Remediate\Tests\Unit\Advisory\Source;

use PHPUnit\Framework\TestCase;
use Remediate\Engine\Advisory\Db\Source\DrupalOrgSource;
use Remediate\Tests\Support\ScriptedDownloader;

final class DrupalOrgSourceTest extends TestCase
{
    public function testReadsContribAdvisoriesAndSpeaksOnlyForDrupalPackages(): void
    {
        $document = ['advisories' => [
            'drupal/webform' => [[
                'advisoryId' => 'SA-CONTRIB-2020-011',
                'packageName' => 'drupal/webform',
                'title' => 'Webform - Critical - Remote Code Execution - SA-CONTRIB-2020-011',
                'link' => 'https://www.drupal.org/sa-contrib-2020-011',
                'cve' => null,
                'affectedVersions' => '<5.11.0',
                'reportedAt' => '2020-05-06 16:43:59',
                'sources' => [['name' => 'Webform - Critical - Remote Code Execution - SA-CONTRIB-2020-011', 'remoteId' => 'SA-CONTRIB-2020-011']],
            ]],
            'acme/lib' => [['advisoryId' => 'SA-CONTRIB-2026-999', 'affectedVersions' => '<2.0.0']],
        ]];
        $downloader = new ScriptedDownloader([DrupalOrgSource::URL => json_encode($document, JSON_THROW_ON_ERROR)]);
        $source = new DrupalOrgSource($downloader);

        $records = $source->fetch(static function (): void {
        });

        self::assertSame('Drupal.org', $source->name());
        self::assertCount(1, $records);
        self::assertSame('SA-CONTRIB-2020-011', $records[0]->canonicalId);
        self::assertSame(['drupal/webform'], $records[0]->packages());
        self::assertSame('<5.11.0', $records[0]->affected[0]->constraint);
        self::assertSame('Drupal.org', $records[0]->affected[0]->source);
        self::assertContains('DRUPAL-CONTRIB-2020-011', $records[0]->aliases, 'the identifier OSV uses for the same advisory');

        $gaps = $source->gaps();
        self::assertCount(1, $gaps, 'a record about a package outside drupal/* is not an advisory, and not silently dropped either');
        self::assertSame('acme/lib', $gaps[0]->package);
        self::assertStringContainsString('drupal/* only', $gaps[0]->reason);
    }

    public function testACoreAdvisoryMergesWithItsOsvTwin(): void
    {
        $document = ['advisories' => ['drupal/core' => [[
            'advisoryId' => 'SA-CORE-2026-013',
            'title' => 'Drupal core - Moderately critical - Third-party libraries - SA-CORE-2026-013',
            'cve' => null,
            'affectedVersions' => '>=11.4.0 <11.4.7',
        ]]]];
        $drupal = (new DrupalOrgSource(new ScriptedDownloader([DrupalOrgSource::URL => json_encode($document, JSON_THROW_ON_ERROR)])))->fetch(static function (): void {
        });
        $osv = new \Remediate\Engine\Advisory\Db\NormalizedAdvisory('DRUPAL-CORE-2026-013', ['DRUPAL-CORE-2026-013'], 'Drupal core', null, null, null, null, [new \Remediate\Engine\Advisory\Db\AffectedRange('drupal/core', '>=11.4.0,<11.4.7', 'OSV')], []);

        $merged = (new \Remediate\Engine\Advisory\Db\Merger())->merge([...$drupal, $osv]);

        self::assertCount(1, $merged, 'one advisory, not the same one twice');
    }

    public function testAnEmptyAnswerIsAnOutage(): void
    {
        $source = new DrupalOrgSource(new ScriptedDownloader([DrupalOrgSource::URL => '{"advisories":[]}']));

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Drupal.org returned no advisories at all');
        $source->fetch(static function (): void {
        });
    }
}
