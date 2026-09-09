<?php

declare(strict_types=1);

namespace Remediate\Engine\Advisory\Db;

use Remediate\Engine\Advisory\Db\Source\AdvisorySourceInterface;

/**
 * Orchestrates a build: fetch every source, merge, write.
 */
final class DatabaseBuilder
{
    /**
     * @param list<AdvisorySourceInterface> $sources
     */
    public function __construct(private readonly array $sources, private readonly Merger $merger = new Merger(), private readonly DatabaseWriter $writer = new DatabaseWriter())
    {
    }

    /**
     * @param callable(string): void $log
     * @param array<string, string>  $extraMeta
     *
     * @return array{path: string, hash: string, advisories: int, conflicts: int, bytes: int, records: int}
     */
    public function build(string $path, callable $log, array $extraMeta = []): array
    {
        $records = [];
        $stats = [];
        foreach ($this->sources as $source) {
            $fetched = $source->fetch($log);
            array_push($records, ...$fetched);
            $stats[] = ['name' => $source->name(), 'fetched_at' => gmdate(DATE_ATOM), 'records' => count($fetched)];
        }
        $log(sprintf('Merging %d records…', count($records)));
        $merged = $this->merger->merge($records);
        $result = $this->writer->write($merged, $stats, $path, $extraMeta);
        $log(sprintf('%d advisories (%d with conflicting ranges), dataset %s, %.1f MB written to %s', $result['advisories'], $result['conflicts'], substr($result['hash'], 0, 12), $result['bytes'] / 1048576, $result['path']));

        return $result + ['records' => count($records)];
    }
}
