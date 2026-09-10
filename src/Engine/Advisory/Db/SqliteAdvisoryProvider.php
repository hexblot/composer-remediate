<?php

declare(strict_types=1);

namespace Remediate\Engine\Advisory\Db;

use Remediate\Engine\Advisory\AdvisoryProvider;
use Remediate\Engine\Advisory\CoverageAware;

final class SqliteAdvisoryProvider implements AdvisoryProvider, CoverageAware
{
    /** @var array<string, list<\Remediate\Engine\Advisory\Advisory>> */
    private array $cache = [];

    /** @var array<string, true> */
    private array $fetched = [];

    /**
     * @param string|null $provenance how the file was established as current (see LocatedDatabase), for the report header
     */
    public function __construct(private readonly Database $database, private readonly ?string $provenance = null)
    {
    }

    public function advisoriesFor(array $packageNames): array
    {
        $wanted = [];
        $missing = [];
        foreach ($packageNames as $name) {
            $name = strtolower($name);
            $wanted[$name] = true;
            if (!isset($this->fetched[$name])) {
                $missing[] = $name;
                $this->fetched[$name] = true;
            }
        }
        if ($missing !== []) {
            foreach ($this->database->advisoriesFor($missing) as $package => $advisories) {
                $this->cache[$package] = $advisories;
            }
        }

        return array_intersect_key($this->cache, $wanted);
    }

    public function describe(): string
    {
        $meta = $this->database->meta();

        $exploit = 'no exploit data';
        if ($this->database->tracksExploits()) {
            $parts = [];
            if (isset($meta['epss_score_date'])) {
                $parts[] = 'EPSS scored ' . substr($meta['epss_score_date'], 0, 10);
            }
            if (isset($meta['kev_date_released'])) {
                $parts[] = 'KEV catalogue ' . substr($meta['kev_date_released'], 0, 10);
            }
            $exploit = $parts === [] ? 'exploit data for ' . ($meta['exploit_count'] ?? '0') . ' CVEs' : implode(', ', $parts);
        }

        return sprintf('advisory database %s (%s advisories, built %s, dataset %s, %s)%s', $this->database->path, $meta['advisory_count'] ?? '?', $meta['built_at'] ?? '?', substr($meta['dataset_hash'] ?? '', 0, 12), $exploit, $this->provenance !== null ? '; ' . $this->provenance : '');
    }

    public function isComplete(): bool
    {
        return true;
    }

    public function coverageWarnings(array $packageNames): array
    {
        if (!$this->database->tracksGaps()) {
            return [sprintf('Advisory database %s was built before coverage gaps were recorded; upstream records the build could not read are unknown. Rebuild it with remediate:db-build.', $this->database->path)];
        }
        $warnings = [];
        foreach ($this->database->gapsFor($packageNames) as $gap) {
            $warnings[] = sprintf('Coverage gap: %s; %s is treated as unaffected by that record.', $gap->describe(), $gap->package ?? 'the package');
        }

        return $warnings;
    }
}
