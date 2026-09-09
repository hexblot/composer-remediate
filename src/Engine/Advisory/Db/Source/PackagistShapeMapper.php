<?php

declare(strict_types=1);

namespace Remediate\Engine\Advisory\Db\Source;

use Remediate\Engine\Advisory\Db\AffectedRange;
use Remediate\Engine\Advisory\Db\CoverageGap;
use Remediate\Engine\Advisory\Db\NormalizedAdvisory;
use Remediate\Engine\Advisory\Db\RangeNormalizer;
use Remediate\Engine\Advisory\Db\SourceRecord;

/**
 * Maps one record in Packagist's advisory API shape (advisoryId, affectedVersions, cve, title, link,
 * severity, reportedAt, sources[]) to a NormalizedAdvisory. Shared by the Packagist source and by
 * local override files, which use the same shape.
 */
final class PackagistShapeMapper
{
    public function __construct(private readonly RangeNormalizer $ranges = new RangeNormalizer())
    {
    }

    /**
     * @param array<mixed> $entry
     * @param-out CoverageGap|null $gap why the record was left out, when it was
     */
    public function map(string $package, array $entry, string $sourceName, ?CoverageGap &$gap = null): ?NormalizedAdvisory
    {
        $gap = null;
        $id = $entry['advisoryId'] ?? null;
        $affected = $entry['affectedVersions'] ?? null;
        if (!is_string($id) || $id === '') {
            $gap = new CoverageGap($sourceName, '(no advisoryId)', strtolower($package), 'record has no advisoryId');

            return null;
        }
        if (!is_string($affected)) {
            $gap = new CoverageGap($sourceName, $id, strtolower($package), 'record has no affectedVersions');

            return null;
        }
        $expression = $this->ranges->validate($affected);
        if ($expression === null) {
            $gap = new CoverageGap($sourceName, $id, strtolower($package), 'unparsable affectedVersions', $affected);

            return null;
        }
        $aliases = [$id];
        $link = is_string($entry['link'] ?? null) ? $entry['link'] : null;
        $sources = [new SourceRecord($sourceName, $id, $link)];
        if (is_string($entry['cve'] ?? null) && $entry['cve'] !== '') {
            $aliases[] = $entry['cve'];
        }
        if (is_string($entry['remoteId'] ?? null) && $entry['remoteId'] !== '') {
            $aliases[] = $entry['remoteId'];
        }
        if (is_array($entry['sources'] ?? null)) {
            foreach ($entry['sources'] as $source) {
                if (is_array($source) && is_string($source['name'] ?? null) && is_string($source['remoteId'] ?? null)) {
                    $aliases[] = $source['remoteId'];
                    $sources[] = new SourceRecord($source['name'], $source['remoteId']);
                }
            }
        }
        $reportedAt = null;
        if (is_string($entry['reportedAt'] ?? null)) {
            try {
                $reportedAt = new \DateTimeImmutable($entry['reportedAt'], new \DateTimeZone('UTC'));
            } catch (\Exception) {
            }
        }
        $ids = array_values(array_unique($aliases));
        usort($ids, static fn (string $a, string $b): int => [NormalizedAdvisory::rankId($a), $a] <=> [NormalizedAdvisory::rankId($b), $b]);

        return new NormalizedAdvisory(
            $ids[0],
            $ids,
            is_string($entry['title'] ?? null) ? $entry['title'] : null,
            $link,
            is_string($entry['severity'] ?? null) ? strtolower($entry['severity']) : null,
            $reportedAt,
            null,
            [new AffectedRange(strtolower($package), $expression, $sourceName)],
            $sources,
        );
    }

    /**
     * Maps a whole document: {"advisories": {"vendor/pkg": [record, …]}}.
     *
     * @param array<mixed> $document
     *
     * @return array{records: list<NormalizedAdvisory>, skipped: int, gaps: list<CoverageGap>}
     */
    public function mapDocument(array $document, string $sourceName): array
    {
        $records = [];
        $skipped = 0;
        $gaps = [];
        $advisories = $document['advisories'] ?? null;
        if (!is_array($advisories)) {
            throw new \RuntimeException(sprintf('%s: document has no "advisories" map', $sourceName));
        }
        foreach ($advisories as $packageName => $list) {
            if (!is_string($packageName) || !is_array($list)) {
                continue;
            }
            foreach ($list as $entry) {
                if (!is_array($entry)) {
                    ++$skipped;
                    $gaps[] = new CoverageGap($sourceName, '(malformed entry)', strtolower($packageName), 'advisory entry is not an object');
                    continue;
                }
                $record = $this->map($packageName, $entry, $sourceName, $gap);
                if ($record === null) {
                    ++$skipped;
                    if ($gap !== null) {
                        $gaps[] = $gap;
                    }
                    continue;
                }
                $records[] = $record;
            }
        }

        return ['records' => $records, 'skipped' => $skipped, 'gaps' => $gaps];
    }
}
