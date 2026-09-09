<?php

declare(strict_types=1);

namespace Remediate\Engine\Advisory\Db;

use Remediate\Engine\Advisory\AdvisoryProvider;

final class SqliteAdvisoryProvider implements AdvisoryProvider
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
}
