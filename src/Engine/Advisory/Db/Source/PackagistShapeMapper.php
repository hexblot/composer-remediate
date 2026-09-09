<?php

declare(strict_types=1);

namespace Remediate\Engine\Advisory\Db\Source;

use Remediate\Engine\Advisory\Db\AffectedRange;
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
     */
    public function map(string $package, array $entry, string $sourceName): ?NormalizedAdvisory
    {
        $id = $entry['advisoryId'] ?? null;
        $affected = $entry['affectedVersions'] ?? null;
        if (!is_string($id) || $id === '' || !is_string($affected)) {
            return null;
        }
        $expression = $this->ranges->validate($affected);
        if ($expression === null) {
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
     * @return array{records: list<NormalizedAdvisory>, skipped: int}
     */
    public function mapDocument(array $document, string $sourceName): array
    {
        $records = [];
        $skipped = 0;
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
                    continue;
                }
                $record = $this->map($packageName, $entry, $sourceName);
                if ($record === null) {
                    ++$skipped;
                    continue;
                }
                $records[] = $record;
            }
        }

        return ['records' => $records, 'skipped' => $skipped];
    }
}
