<?php

declare(strict_types=1);

namespace Remediate\Engine\Advisory\Db\Enrichment;

use Composer\Util\HttpDownloader;

/**
 * CISA's Known Exploited Vulnerabilities catalogue: a JSON document with `catalogVersion`,
 * `dateReleased` and one `vulnerabilities[]` entry per CVE with `cveID`, `dateAdded` and
 * `knownRansomwareCampaignUse`.
 */
final class KevSource implements EnrichmentSourceInterface
{
    public const URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

    /**
     * @param string|null $localFile a downloaded copy of the catalogue to read instead of the feed
     */
    public function __construct(
        private readonly HttpDownloader $downloader,
        private readonly ?string $localFile = null,
        private readonly string $url = self::URL,
    ) {
    }

    public function name(): string
    {
        return 'KEV';
    }

    public function fetch(callable $log): array
    {
        if ($this->localFile !== null) {
            $log('KEV: reading ' . $this->localFile);
            $raw = @file_get_contents($this->localFile);
            if ($raw === false) {
                throw new \RuntimeException(sprintf('Cannot read KEV file %s', $this->localFile));
            }
            $data = json_decode($raw, true);
        } else {
            $log('KEV: downloading the CISA catalogue…');
            $data = $this->downloader->get($this->url)->decodeJson();
        }
        if (!is_array($data) || !is_array($data['vulnerabilities'] ?? null)) {
            throw new \RuntimeException('KEV catalogue has no "vulnerabilities" list');
        }
        $records = [];
        foreach ($data['vulnerabilities'] as $entry) {
            if (!is_array($entry) || !is_string($entry['cveID'] ?? null)) {
                continue;
            }
            $cve = strtoupper(trim($entry['cveID']));
            if (preg_match('{^CVE-\d{4}-\d+$}', $cve) !== 1) {
                continue;
            }
            $added = null;
            if (is_string($entry['dateAdded'] ?? null) && $entry['dateAdded'] !== '') {
                try {
                    $added = new \DateTimeImmutable($entry['dateAdded'], new \DateTimeZone('UTC'));
                } catch (\Exception) {
                }
            }
            $records[$cve] = new ExploitRecord($cve, null, null, $added ?? new \DateTimeImmutable('1970-01-01', new \DateTimeZone('UTC')), strtolower((string) ($entry['knownRansomwareCampaignUse'] ?? '')) === 'known');
        }
        $meta = ['kev_count' => (string) count($records)];
        foreach (['catalogVersion' => 'kev_catalog_version', 'dateReleased' => 'kev_date_released'] as $field => $key) {
            if (is_scalar($data[$field] ?? null)) {
                $meta[$key] = (string) $data[$field];
            }
        }
        $log(sprintf('KEV: %d known exploited CVEs%s', count($records), isset($meta['kev_date_released']) ? ', catalogue released ' . $meta['kev_date_released'] : ''));

        return ['records' => $records, 'meta' => $meta];
    }
}
