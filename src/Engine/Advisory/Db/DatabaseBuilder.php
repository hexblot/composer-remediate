<?php

declare(strict_types=1);

namespace Remediate\Engine\Advisory\Db;

use Remediate\Engine\Advisory\Db\Enrichment\EnrichmentSourceInterface;
use Remediate\Engine\Advisory\Db\Enrichment\ExploitRecord;
use Remediate\Engine\Advisory\Db\Source\AdvisorySourceInterface;

/**
 * Orchestrates a build: fetch every source, merge, enrich the CVEs with exploit data, write.
 */
final class DatabaseBuilder
{
    /**
     * @param list<AdvisorySourceInterface>    $sources
     * @param list<EnrichmentSourceInterface> $enrichments exploit-data feeds; a feed that fails is recorded in the
     *                                                     metadata and the database is built without it
     */
    public function __construct(
        private readonly array $sources,
        private readonly Merger $merger = new Merger(),
        private readonly DatabaseWriter $writer = new DatabaseWriter(),
        private readonly array $enrichments = [],
    ) {
    }

    /**
     * @param callable(string): void $log
     * @param array<string, string>  $extraMeta
     *
     * @return array{path: string, hash: string, advisories: int, conflicts: int, gaps: int, exploits: int, bytes: int, records: int, enrichment_errors: list<string>}
     */
    public function build(string $path, callable $log, array $extraMeta = []): array
    {
        $records = [];
        $gaps = [];
        $stats = [];
        foreach ($this->sources as $source) {
            $fetched = $source->fetch($log);
            array_push($records, ...$fetched);
            array_push($gaps, ...$source->gaps());
            $stats[] = ['name' => $source->name(), 'fetched_at' => gmdate(DATE_ATOM), 'records' => count($fetched), 'gaps' => count($source->gaps())];
        }
        $log(sprintf('Merging %d records…', count($records)));
        $merged = $this->merger->merge($records);
        [$exploits, $enrichmentMeta, $errors] = $this->enrich($merged, $log);
        $result = $this->writer->write($merged, $stats, $path, $enrichmentMeta + $extraMeta, $gaps, $exploits);
        $log(sprintf('%d advisories (%d with conflicting ranges, %d coverage gap%s, exploit data for %d CVE%s), dataset %s, %.1f MB written to %s', $result['advisories'], $result['conflicts'], $result['gaps'], $result['gaps'] === 1 ? '' : 's', $result['exploits'], $result['exploits'] === 1 ? '' : 's', substr($result['hash'], 0, 12), $result['bytes'] / 1048576, $result['path']));

        return $result + ['records' => count($records), 'enrichment_errors' => $errors];
    }

    /**
     * Fetches every enrichment feed and keeps only the CVEs the merged advisories name: EPSS scores
     * hundreds of thousands of CVEs, a few thousand of which concern Composer packages.
     *
     * @param list<NormalizedAdvisory> $advisories
     * @param callable(string): void   $log
     *
     * @return array{array<string, ExploitRecord>, array<string, string>, list<string>}
     */
    private function enrich(array $advisories, callable $log): array
    {
        if ($this->enrichments === []) {
            return [[], [], []];
        }
        $wanted = [];
        foreach ($advisories as $advisory) {
            foreach ($advisory->aliases as $alias) {
                if (preg_match('{^CVE-\d{4}-\d+$}i', $alias) === 1) {
                    $wanted[strtoupper($alias)] = true;
                }
            }
        }
        $exploits = [];
        $meta = [];
        $errors = [];
        foreach ($this->enrichments as $source) {
            try {
                $fetched = $source->fetch($log);
            } catch (\RuntimeException $e) {
                $errors[] = sprintf('%s: %s', $source->name(), trim(explode("\n", $e->getMessage())[0]));
                $log(sprintf('<warning>%s unavailable (%s); the database is built without it.</warning>', $source->name(), $e->getMessage()));
                continue;
            }
            $meta += $fetched['meta'];
            $matched = 0;
            foreach ($fetched['records'] as $cve => $record) {
                $cve = strtoupper((string) $cve);
                if (!isset($wanted[$cve])) {
                    continue;
                }
                ++$matched;
                $exploits[$cve] = isset($exploits[$cve]) ? $exploits[$cve]->merge($record) : $record;
            }
            $log(sprintf('%s: %d of the %d CVEs in this database have data', $source->name(), $matched, count($wanted)));
        }
        if ($errors !== []) {
            $meta['enrichment_errors'] = json_encode($errors, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        }
        ksort($exploits);

        return [$exploits, $meta, $errors];
    }
}
