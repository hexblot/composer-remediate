<?php

declare(strict_types=1);

namespace Remediate\Engine\Advisory\Db\Enrichment;

use Composer\Util\HttpDownloader;

/**
 * FIRST's Exploit Prediction Scoring System: a daily gzip-compressed CSV with one row per scored
 * CVE (`cve,epss,percentile`) behind a comment line naming the model version and score date.
 */
final class EpssSource implements EnrichmentSourceInterface
{
    public const URL = 'https://epss.cyentia.com/epss_scores-current.csv.gz';

    /**
     * @param string|null $localFile a downloaded copy (plain or gzip-compressed CSV) to read instead of the feed
     */
    public function __construct(
        private readonly HttpDownloader $downloader,
        private readonly string $tempDir,
        private readonly ?string $localFile = null,
        private readonly string $url = self::URL,
    ) {
    }

    public function name(): string
    {
        return 'EPSS';
    }

    public function fetch(callable $log): array
    {
        if ($this->localFile !== null) {
            $log('EPSS: reading ' . $this->localFile);
            $raw = @file_get_contents($this->localFile);
            if ($raw === false) {
                throw new \RuntimeException(sprintf('Cannot read EPSS file %s', $this->localFile));
            }
        } else {
            $log('EPSS: downloading the current scores…');
            @mkdir($this->tempDir, 0700, true);
            $file = $this->tempDir . '/' . sha1($this->url) . '.csv.gz';
            try {
                $this->downloader->copy($this->url, $file);
                $raw = (string) file_get_contents($file);
            } finally {
                @unlink($file);
            }
        }
        $csv = str_starts_with($raw, "\x1f\x8b") ? gzdecode($raw) : $raw;
        if ($csv === false) {
            throw new \RuntimeException('EPSS feed is not valid gzip data');
        }
        $meta = [];
        $records = [];
        $columns = null;
        foreach (preg_split('/\r?\n/', $csv) ?: [] as $line) {
            if ($line === '') {
                continue;
            }
            if ($line[0] === '#') {
                // #model_version:v2025.03.14,score_date:2026-09-09T00:00:00+0000
                foreach (explode(',', substr($line, 1)) as $pair) {
                    $parts = explode(':', $pair, 2);
                    if (count($parts) === 2) {
                        $meta['epss_' . trim($parts[0])] = trim($parts[1]);
                    }
                }
                continue;
            }
            $cells = str_getcsv($line, ',', '"', '');
            if ($columns === null) {
                $columns = array_map(static fn ($c): string => strtolower(trim((string) $c)), $cells);
                if (!in_array('cve', $columns, true) || !in_array('epss', $columns, true)) {
                    throw new \RuntimeException('EPSS feed has no cve/epss columns: ' . $line);
                }
                continue;
            }
            $row = [];
            foreach ($columns as $i => $name) {
                $row[$name] = isset($cells[$i]) ? trim((string) $cells[$i]) : '';
            }
            $cve = strtoupper($row['cve'] ?? '');
            if (preg_match('{^CVE-\d{4}-\d+$}', $cve) !== 1 || !is_numeric($row['epss'] ?? '')) {
                continue;
            }
            $percentile = $row['percentile'] ?? '';
            $records[$cve] = new ExploitRecord($cve, (float) $row['epss'], is_numeric($percentile) ? (float) $percentile : null);
        }
        if ($columns === null) {
            throw new \RuntimeException('EPSS feed is empty');
        }
        $meta['epss_count'] = (string) count($records);
        $log(sprintf('EPSS: %d scored CVEs%s', count($records), isset($meta['epss_score_date']) ? ', scored ' . $meta['epss_score_date'] : ''));

        return ['records' => $records, 'meta' => $meta];
    }
}
