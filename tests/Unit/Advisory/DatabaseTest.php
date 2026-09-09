<?php

declare(strict_types=1);

namespace Remediate\Tests\Unit\Advisory;

use Composer\Semver\Semver;
use PHPUnit\Framework\TestCase;
use Remediate\Engine\Advisory\Db\AffectedRange;
use Remediate\Engine\Advisory\Db\Database;
use Remediate\Engine\Advisory\Db\DatabaseWriter;
use Remediate\Engine\Advisory\Db\Merger;
use Remediate\Engine\Advisory\Db\NormalizedAdvisory;
use Remediate\Engine\Advisory\Db\RangeNormalizer;
use Remediate\Engine\Advisory\Db\SourceRecord;
use Remediate\Engine\Advisory\Db\SqliteAdvisoryProvider;

final class DatabaseTest extends TestCase
{
    public function testOsvRangesBecomeComposerConstraints(): void
    {
        $n = new RangeNormalizer();
        self::assertSame('>=3.0.0,<3.11.0|>=3.12.0,<3.14.0', $n->fromOsv([
            ['type' => 'ECOSYSTEM', 'events' => [['introduced' => '3.0.0'], ['fixed' => '3.11.0'], ['introduced' => '3.12.0'], ['fixed' => '3.14.0']]],
        ]));
        self::assertSame('<1.44.7', $n->fromOsv([['type' => 'ECOSYSTEM', 'events' => [['introduced' => '0'], ['fixed' => '1.44.7']]]]));
        self::assertSame('>=2.0.0,<=2.3.1', $n->fromOsv([['type' => 'ECOSYSTEM', 'events' => [['introduced' => '2.0.0'], ['last_affected' => '2.3.1']]]]));
        self::assertSame('>=5.0.0', $n->fromOsv([['type' => 'ECOSYSTEM', 'events' => [['introduced' => '5.0.0']]]]));
        self::assertSame('==1.2.3|==1.2.4', $n->fromOsv([], ['1.2.3', '1.2.4']));
        self::assertNull($n->fromOsv([['type' => 'GIT', 'events' => [['introduced' => 'abc']]]]));
    }

    public function testFriendsOfPhpBranchesBecomeComposerConstraints(): void
    {
        $n = new RangeNormalizer();
        self::assertSame('>=1.0.0,<1.44.7|>=3.0.0,<3.4.3', $n->fromFriendsOfPhp([
            '1.x' => ['time' => '2022-09-28 12:00:00', 'versions' => ['>=1.0.0', '<1.44.7']],
            '3.x' => ['time' => '2022-09-28 12:00:00', 'versions' => ['>=3.0.0', '<3.4.3']],
        ]));
        self::assertNull($n->fromFriendsOfPhp(['x' => ['versions' => ['not a constraint !!']]]));
    }

    public function testFingerprintIsSemantic(): void
    {
        $n = new RangeNormalizer();
        self::assertSame($n->fingerprint('>=7,<7.4.4|>=4,<6.5.7'), $n->fingerprint('>=4.0.0,<6.5.7|>=7.0.0,<7.4.4'));
        self::assertSame($n->fingerprint('<1.5'), $n->fingerprint('<1.5.0'));
        self::assertNotSame($n->fingerprint('<1.5.0'), $n->fingerprint('<1.6.0'));
    }

    public function testMergerGroupsByAliasAndFlagsConflicts(): void
    {
        $packagist = new NormalizedAdvisory('PKSA-1111', ['PKSA-1111', 'CVE-2024-1', 'GHSA-aaaa'], 'Title A', 'https://a', 'high', new \DateTimeImmutable('2024-01-02'), null, [new AffectedRange('acme/lib', '<1.5.0', 'Packagist')], [new SourceRecord('Packagist', 'PKSA-1111')]);
        $osv = new NormalizedAdvisory('GHSA-aaaa', ['GHSA-aaaa', 'CVE-2024-1'], 'Title B', 'https://b', 'medium', new \DateTimeImmutable('2024-01-01'), null, [new AffectedRange('acme/lib', '>=1.0.0,<1.5.0', 'OSV')], [new SourceRecord('OSV', 'GHSA-aaaa')]);
        $unrelated = new NormalizedAdvisory('CVE-2024-9', ['CVE-2024-9'], null, null, null, null, null, [new AffectedRange('other/pkg', '<2.0', 'OSV')], [new SourceRecord('OSV', 'GHSA-zzzz')]);

        $merged = (new Merger())->merge([$packagist, $osv, $unrelated]);
        self::assertCount(2, $merged);
        self::assertSame('CVE-2024-1', $merged[0]->canonicalId);
        self::assertSame(['CVE-2024-1', 'GHSA-aaaa', 'PKSA-1111'], $merged[0]->aliases);
        self::assertSame('high', $merged[0]->severity);
        self::assertSame('2024-01-01', $merged[0]->reportedAt?->format('Y-m-d'));
        self::assertCount(2, $merged[0]->affected);
        self::assertSame(['acme/lib'], $merged[0]->conflicts, 'different range expressions must be flagged, not silently merged');
        self::assertSame('CVE-2024-9', $merged[1]->canonicalId);
    }

    public function testWriteThenReadRoundTrip(): void
    {
        $advisories = [
            new NormalizedAdvisory('CVE-2024-1', ['CVE-2024-1', 'GHSA-aaaa'], 'Title', 'https://a', 'high', new \DateTimeImmutable('2024-01-01T00:00:00Z'), null, [new AffectedRange('acme/lib', '<1.5.0', 'Packagist'), new AffectedRange('acme/lib', '>=1.0.0,<1.6.0', 'OSV')], [new SourceRecord('Packagist', 'PKSA-1'), new SourceRecord('OSV', 'GHSA-aaaa')], ['acme/lib']),
            new NormalizedAdvisory('GHSA-gone', ['GHSA-gone'], 'Withdrawn', null, null, null, new \DateTimeImmutable('2024-02-01T00:00:00Z'), [new AffectedRange('acme/lib', '*', 'OSV')], [new SourceRecord('OSV', 'GHSA-gone')]),
        ];
        $path = sys_get_temp_dir() . '/remediate-test-' . bin2hex(random_bytes(4)) . '.sqlite';
        try {
            $result = (new DatabaseWriter())->write($advisories, [['name' => 'test', 'fetched_at' => '2024-01-01T00:00:00Z', 'records' => 2]], $path);
            self::assertSame(2, $result['advisories']);
            self::assertSame(1, $result['conflicts']);
            self::assertSame(DatabaseWriter::datasetHash($advisories), $result['hash']);

            $db = Database::open($path);
            self::assertSame('1', $db->meta()['schema_version']);
            self::assertSame($result['hash'], $db->meta()['dataset_hash']);
            $provider = new SqliteAdvisoryProvider($db);
            $found = $provider->advisoriesFor(['acme/lib', 'nothing/here']);
            self::assertArrayHasKey('acme/lib', $found);
            self::assertCount(1, $found['acme/lib'], 'withdrawn advisories are not returned');
            $advisory = $found['acme/lib'][0];
            self::assertSame('CVE-2024-1', $advisory->id);
            self::assertSame('CVE-2024-1', $advisory->cve);
            self::assertSame('high', $advisory->severity);
            self::assertCount(2, $advisory->sources);
            // union of both sources' ranges: 1.5.5 is affected per OSV even though Packagist says fixed
            self::assertTrue(Semver::satisfies('1.5.5', $advisory->affectedVersions->getPrettyString()));
            self::assertTrue($advisory->affectsVersion('1.4.0.0'));
            self::assertFalse($advisory->affectsVersion('1.6.0.0'));
            self::assertStringContainsString('2 advisories', $provider->describe());
        } finally {
            @unlink($path);
        }
    }

    public function testDatasetHashIgnoresSourceMetadataButNotRanges(): void
    {
        $a = new NormalizedAdvisory('CVE-1', ['CVE-1'], 't', null, null, null, null, [new AffectedRange('x/y', '<1', 'OSV')], [new SourceRecord('OSV', 'a', null, new \DateTimeImmutable('2024-01-01'))]);
        $b = new NormalizedAdvisory('CVE-1', ['CVE-1'], 'other title', null, null, null, null, [new AffectedRange('x/y', '<1', 'OSV')], [new SourceRecord('OSV', 'a', null, new \DateTimeImmutable('2025-01-01'))]);
        $c = new NormalizedAdvisory('CVE-1', ['CVE-1'], 't', null, null, null, null, [new AffectedRange('x/y', '<2', 'OSV')], [new SourceRecord('OSV', 'a')]);
        self::assertSame(DatabaseWriter::datasetHash([$a]), DatabaseWriter::datasetHash([$b]));
        self::assertNotSame(DatabaseWriter::datasetHash([$a]), DatabaseWriter::datasetHash([$c]));
    }

    public function testJsonFileSourceReadsPrivateAdvisories(): void
    {
        $path = sys_get_temp_dir() . '/remediate-private-' . bin2hex(random_bytes(4)) . '.json';
        file_put_contents($path, json_encode(['advisories' => ['Company/Internal' => [
            ['advisoryId' => 'COMPANY-2026-001', 'affectedVersions' => '<2.1.4', 'title' => 'Internal issue', 'severity' => 'High', 'reportedAt' => '2026-01-15 10:00:00'],
            ['advisoryId' => 'broken', 'affectedVersions' => 'not a range !!'],
        ]]]));
        try {
            $source = new \Remediate\Engine\Advisory\Db\Source\JsonFileSource($path);
            $messages = [];
            $records = $source->fetch(static function (string $m) use (&$messages): void { $messages[] = $m; });
            self::assertCount(1, $records);
            self::assertSame('COMPANY-2026-001', $records[0]->canonicalId);
            self::assertSame('company/internal', $records[0]->affected[0]->package);
            self::assertSame('high', $records[0]->severity);
            self::assertStringStartsWith('local:', $records[0]->sources[0]->name);
            self::assertStringContainsString('1 skipped', $messages[0]);
        } finally {
            @unlink($path);
        }
    }
}
