<?php

declare(strict_types=1);

namespace Remediate\Engine\Advisory\Db\Source;

use Composer\Util\HttpDownloader;
use Remediate\Engine\Advisory\Db\AffectedRange;
use Remediate\Engine\Advisory\Db\CoverageGap;
use Remediate\Engine\Advisory\Db\NormalizedAdvisory;
use Remediate\Engine\Advisory\Db\PackageName;
use Remediate\Engine\Advisory\Db\RangeNormalizer;
use Remediate\Engine\Advisory\Db\SourceRecord;

/**
 * OSV's per-ecosystem dump: a zip of one JSON document per vulnerability in the OSV schema.
 */
final class OsvDumpSource implements AdvisorySourceInterface
{
    public const URL = 'https://osv-vulnerabilities.storage.googleapis.com/Packagist/all.zip';

    /** @var list<CoverageGap> */
    private array $gaps = [];

    public function __construct(
        private readonly HttpDownloader $downloader,
        private readonly string $tempDir,
        private readonly RangeNormalizer $ranges = new RangeNormalizer(),
        private readonly string $url = self::URL,
    ) {
    }

    public function name(): string
    {
        return 'OSV';
    }

    public function fetch(callable $log): array
    {
        $log('OSV: downloading the Packagist ecosystem archive…');
        $records = [];
        $this->gaps = [];
        $skipped = ['invalid JSON' => 0, 'no Packagist package' => 0, 'no usable range' => 0];
        $partial = 0;
        $unreadable = 0;
        $reader = new ZipArchiveReader($this->downloader, $this->tempDir);
        $entries = $reader->each($this->url, static fn (string $name): bool => str_ends_with($name, '.json'), function (string $name, string $contents) use (&$records, &$skipped, &$partial): void {
            $doc = json_decode($contents, true);
            if (!is_array($doc)) {
                ++$skipped['invalid JSON'];
                $this->gaps[] = new CoverageGap('OSV', basename($name, '.json'), null, 'invalid JSON');

                return;
            }
            $record = $this->record($doc, $reason, $packages, $unreadable);
            if ($record === null) {
                $skipped[$reason ?? 'no usable range'] = ($skipped[$reason ?? 'no usable range'] ?? 0) + 1;
                if ($reason !== 'no Packagist package') {
                    // A record about a Packagist package that could not be read is a coverage gap for
                    // that package. Where the record said which parts it could not read, those are the
                    // gaps: a part that named no package is its own uncertainty and must not be
                    // replaced by the packages other parts happened to name, because nothing then
                    // records that something unattributable was lost.
                    $id = is_string($doc['id'] ?? null) ? $doc['id'] : basename($name, '.json');
                    $targets = $unreadable;
                    if ($targets === []) {
                        foreach ($packages === [] ? [null] : $packages as $package) {
                            $targets[] = [$package, $reason ?? 'no usable range'];
                        }
                    }
                    foreach ($targets as [$package, $why]) {
                        $this->gaps[] = new CoverageGap('OSV', $id, $package, $why);
                    }
                }

                return;
            }
            $records[] = $record;
            // A readable document may still carry a package entry whose range cannot be expressed; that
            // package's coverage is incomplete even though the record is kept for the others.
            foreach ($unreadable as [$package, $why]) {
                ++$partial;
                $this->gaps[] = new CoverageGap('OSV', $record->sources[0]->remoteId, $package, $why);
            }
        }, function (string $name) use (&$unreadable): void {
            // The archive held this document and its bytes could not be read. Whatever advisories it
            // carried are unknown, so it is a gap attributed to no package: something is missing from
            // coverage and nothing here can say for which package.
            ++$unreadable;
            $this->gaps[] = new CoverageGap('OSV', basename($name, '.json'), null, 'archive entry could not be read');
        });
        $reasons = array_filter($skipped);
        $log(sprintf(
            'OSV: %d documents, %d records%s%s',
            $entries,
            count($records),
            $reasons !== [] ? ', skipped: ' . implode(', ', array_map(static fn (string $k, int $v): string => "$v $k", array_keys($reasons), $reasons)) . ' (Packagist records recorded as coverage gaps)' : '',
            $partial > 0 ? sprintf(', %d package entr%s unreadable inside kept records (recorded as coverage gaps)', $partial, $partial === 1 ? 'y' : 'ies') : '',
        ) . ($unreadable > 0 ? sprintf(' — %d archive entr%s could not be read (recorded as coverage gaps)', $unreadable, $unreadable === 1 ? 'y' : 'ies') : ''));

        self::refuseEmpty($records, $this->gaps, 'OSV');

        return $records;
    }

    /**
     * A public advisory feed always has thousands of records. Nothing at all means the feed answered
     * without its data: an empty document, an archive with nothing inside, a mirror serving a
     * placeholder. That is an outage wearing a success, and accepting it would build a database
     * missing a whole source, publish it checksum-verified and attested, and report locks clean that
     * are not.
     *
     * Records the source read and could not interpret are a different thing: they come back as
     * coverage gaps, which are reported and gate a clean result on their own. A feed is only refused
     * when it produced neither.
     *
     * @param list<\Remediate\Engine\Advisory\Db\NormalizedAdvisory> $records
     * @param list<\Remediate\Engine\Advisory\Db\CoverageGap>        $gaps
     */
    private static function refuseEmpty(array $records, array $gaps, string $source): void
    {
        if ($records === [] && $gaps === []) {
            throw new \RuntimeException(sprintf('%s returned no advisories at all, and nothing it could not read either. A feed that answers successfully with no data is an outage, not an empty world; the build stops rather than publish a database missing this source.', $source));
        }
    }

    public function gaps(): array
    {
        return $this->gaps;
    }

    /**
     * @param array<mixed>      $doc
     * @param list<string>|null $packages
     * @param list<array{string|null, string}>|null $unreadable
     * @param-out string|null $reason
     * @param-out list<string> $packages   Packagist packages the document names, for gap reporting
     * @param-out list<array{string|null, string}> $unreadable package and reason for each part of the record that could not be read although the record is kept; the package is null when the entry did not say which it was about
     */
    private function record(array $doc, ?string &$reason = null, ?array &$packages = null, ?array &$unreadable = null): ?NormalizedAdvisory
    {
        $reason = null;
        $packages = [];
        $unreadable = [];
        $id = $doc['id'] ?? null;
        if (!is_string($id) || $id === '') {
            $reason = 'invalid JSON';

            return null;
        }
        $affected = [];
        $perPackage = [];
        $sawPackagist = false;
        // A document with no affected list is about nothing this cares about. A document whose affected
        // list is there but cannot be read is a different thing: it might have been about a Packagist
        // package, and nothing here can say which, so it becomes a gap attributed to no package rather
        // than being counted with the records that are simply about another ecosystem.
        $affectedList = $doc['affected'] ?? null;
        if ($affectedList !== null && !is_array($affectedList)) {
            $reason = 'unreadable affected list';

            return null;
        }
        foreach (is_array($affectedList) ? $affectedList : [] as $entry) {
            // An entry that cannot be read at all might have been about a Packagist package. The rest
            // of the document is still worth keeping, so the record survives and the unreadable entry
            // becomes a gap attributed to no package, the same way a range that cannot be expressed
            // becomes one attributed to its package.
            // An entry carrying no readable package object, whether the key is absent, null or not an
            // object, says nothing about which package it is for. Saying nothing is not saying "another
            // ecosystem's": the entry may well be about a locked package, and the rest of the document
            // is still worth keeping, so the record survives and the entry becomes an unattributed gap.
            if (!is_array($entry) || !is_array($entry['package'] ?? null)) {
                $unreadable[] = [null, 'unreadable affected entry'];
                continue;
            }
            $package = $entry['package'];
            // Only an identity positively read as another ecosystem's is out of scope. One this cannot
            // read (no ecosystem, an ecosystem that is not text, or a name that is missing, not text,
            // or not a package name a lock could hold) may well be about a locked package, and
            // classifying it as somebody else's ecosystem is a guess that reads as complete coverage.
            // It becomes a gap instead, attributed to the name when the name itself was readable and
            // to no package when it was not, since a name nothing can match attributes nothing.
            $ecosystem = $package['ecosystem'] ?? null;
            $name = PackageName::canonical($package['name'] ?? null);
            if (is_string($ecosystem) && $ecosystem !== '' && strtolower($ecosystem) !== 'packagist') {
                continue;
            }
            if (!is_string($ecosystem) || $ecosystem === '' || $name === null) {
                $unreadable[] = [$name, 'unreadable package identity'];
                continue;
            }
            $sawPackagist = true;
            $packages[] = $name;
            // Anything in these lists that is not the shape it should be is not filtered away: dropping
            // it here would hand normalisation a list that looks complete, and the record would come
            // back with narrower coverage and nothing to say so.
            // A container that is there but is not a list is not an absent one. Turning it into an
            // empty list is how "this entry names ranges I could not read" became "this entry names no
            // ranges", which reads as complete coverage.
            // A container present as null is not an absent one either: `ranges: null` is the feed
            // saying nothing readable where ranges belong, so it is treated the same as a scalar there.
            $malformed = (array_key_exists('ranges', $entry) && !is_array($entry['ranges'])) || (array_key_exists('versions', $entry) && !is_array($entry['versions']));
            $rawRanges = is_array($entry['ranges'] ?? null) ? array_values($entry['ranges']) : [];
            $rawVersions = is_array($entry['versions'] ?? null) ? array_values($entry['versions']) : [];
            /** @var list<array<string, mixed>> $ranges */
            $ranges = array_values(array_filter($rawRanges, 'is_array'));
            /** @var list<string> $versions */
            $versions = array_values(array_filter($rawVersions, 'is_string'));
            $malformed = $malformed || count($ranges) !== count($rawRanges) || count($versions) !== count($rawVersions);
            $expression = $malformed ? null : $this->ranges->fromOsv($ranges, $versions);
            if ($expression !== null) {
                $perPackage[$name][] = $expression;
            } else {
                $unreadable[] = [$name, 'no usable range'];
            }
        }
        $unreadable = array_values(array_unique($unreadable, SORT_REGULAR));
        foreach ($perPackage as $name => $expressions) {
            $affected[] = new AffectedRange($name, implode('|', array_unique($expressions)), 'OSV');
        }
        if ($affected === []) {
            // "No Packagist package" is the one reason that records no gap, because most of this feed
            // is about other ecosystems. A document that had something this could not read is never
            // filed under it, whatever else did or did not survive: that would throw away the very
            // uncertainty the unreadable parts were noted for.
            $reason = match (true) {
                $unreadable !== [] => (string) $unreadable[0][1],
                $sawPackagist => 'no usable range',
                default => 'no Packagist package',
            };

            return null;
        }
        $aliases = [$id];
        foreach (is_array($doc['aliases'] ?? null) ? $doc['aliases'] : [] as $alias) {
            if (is_string($alias) && $alias !== '') {
                $aliases[] = $alias;
            }
        }
        $ids = array_values(array_unique($aliases));
        usort($ids, static fn (string $a, string $b): int => [NormalizedAdvisory::rankId($a), $a] <=> [NormalizedAdvisory::rankId($b), $b]);

        $link = 'https://osv.dev/vulnerability/' . $id;
        foreach (is_array($doc['references'] ?? null) ? $doc['references'] : [] as $reference) {
            if (is_array($reference) && ($reference['type'] ?? null) === 'ADVISORY' && is_string($reference['url'] ?? null)) {
                $link = $reference['url'];
                break;
            }
        }
        $severity = null;
        if (is_array($doc['database_specific'] ?? null) && is_string($doc['database_specific']['severity'] ?? null)) {
            $severity = strtolower($doc['database_specific']['severity']);
            $severity = $severity === 'moderate' ? 'medium' : $severity;
        }

        return new NormalizedAdvisory(
            $ids[0],
            $ids,
            is_string($doc['summary'] ?? null) ? $doc['summary'] : null,
            $link,
            $severity,
            self::date($doc['published'] ?? null),
            self::date($doc['withdrawn'] ?? null),
            $affected,
            [new SourceRecord('OSV', $id, 'https://osv.dev/vulnerability/' . $id, self::date($doc['modified'] ?? null))],
        );
    }

    private static function date(mixed $value): ?\DateTimeImmutable
    {
        if (!is_string($value) || $value === '') {
            return null;
        }
        try {
            return new \DateTimeImmutable($value, new \DateTimeZone('UTC'));
        } catch (\Exception) {
            return null;
        }
    }
}
