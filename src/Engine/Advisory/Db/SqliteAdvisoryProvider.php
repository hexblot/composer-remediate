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

    public function __construct(private readonly Database $database)
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

        return sprintf('advisory database %s (%s advisories, built %s, dataset %s)', $this->database->path, $meta['advisory_count'] ?? '?', $meta['built_at'] ?? '?', substr($meta['dataset_hash'] ?? '', 0, 12));
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
