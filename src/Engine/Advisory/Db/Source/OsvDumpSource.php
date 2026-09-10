<?php

declare(strict_types=1);

namespace Remediate\Engine\Advisory\Db\Source;

use Composer\Util\HttpDownloader;
use Remediate\Engine\Advisory\Db\AffectedRange;
use Remediate\Engine\Advisory\Db\CoverageGap;
use Remediate\Engine\Advisory\Db\NormalizedAdvisory;
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
                ++$skipped[$reason ?? 'no usable range'];
                if ($reason !== 'no Packagist package') {
                    // A record about a Packagist package that could not be read is a coverage gap for that package.
                    $id = is_string($doc['id'] ?? null) ? $doc['id'] : basename($name, '.json');
                    foreach ($packages === [] ? [null] : $packages as $package) {
                        $this->gaps[] = new CoverageGap('OSV', $id, $package, $reason ?? 'no usable range');
                    }
                }

                return;
            }
            $records[] = $record;
            // A readable document may still carry a package entry whose range cannot be expressed; that
            // package's coverage is incomplete even though the record is kept for the others.
            foreach ($unreadable as $package) {
                ++$partial;
                $this->gaps[] = new CoverageGap('OSV', $record->sources[0]->remoteId, $package, 'no usable range');
            }
        });
        $reasons = array_filter($skipped);
        $log(sprintf(
            'OSV: %d documents, %d records%s%s',
            $entries,
            count($records),
            $reasons !== [] ? ', skipped: ' . implode(', ', array_map(static fn (string $k, int $v): string => "$v $k", array_keys($reasons), $reasons)) . ' (Packagist records recorded as coverage gaps)' : '',
            $partial > 0 ? sprintf(', %d package entr%s unreadable inside kept records (recorded as coverage gaps)', $partial, $partial === 1 ? 'y' : 'ies') : '',
        ));

        return $records;
    }

    public function gaps(): array
    {
        return $this->gaps;
    }

    /**
     * @param array<mixed>      $doc
     * @param list<string>|null $packages
     * @param list<string>|null $unreadable
     * @param-out string|null $reason
     * @param-out list<string> $packages   Packagist packages the document names, for gap reporting
     * @param-out list<string> $unreadable Packagist packages whose range could not be expressed although the record is kept
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
        foreach (is_array($doc['affected'] ?? null) ? $doc['affected'] : [] as $entry) {
            if (!is_array($entry) || !is_array($entry['package'] ?? null)) {
                continue;
            }
            $package = $entry['package'];
            if (strtolower((string) ($package['ecosystem'] ?? '')) !== 'packagist' || !is_string($package['name'] ?? null)) {
                continue;
            }
            $sawPackagist = true;
            $packages[] = strtolower($package['name']);
            /** @var list<array<string, mixed>> $ranges */
            $ranges = is_array($entry['ranges'] ?? null) ? array_values(array_filter($entry['ranges'], 'is_array')) : [];
            /** @var list<string> $versions */
            $versions = is_array($entry['versions'] ?? null) ? array_values(array_filter($entry['versions'], 'is_string')) : [];
            $expression = $this->ranges->fromOsv($ranges, $versions);
            if ($expression !== null) {
                $perPackage[strtolower($package['name'])][] = $expression;
            } else {
                $unreadable[] = strtolower($package['name']);
            }
        }
        $unreadable = array_values(array_unique($unreadable));
        foreach ($perPackage as $name => $expressions) {
            $affected[] = new AffectedRange($name, implode('|', array_unique($expressions)), 'OSV');
        }
        if ($affected === []) {
            $reason = $sawPackagist ? 'no usable range' : 'no Packagist package';

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
