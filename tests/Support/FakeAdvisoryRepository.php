<?php

declare(strict_types=1);

namespace Remediate\Tests\Support;

use Composer\Advisory\PartialSecurityAdvisory;
use Composer\Repository\AdvisoryProviderInterface;
use Composer\Repository\ArrayRepository;

/**
 * A Composer repository that answers advisory queries from a script, the way packagist.org does
 * over HTTP, and records every query it receives.
 */
final class FakeAdvisoryRepository extends ArrayRepository implements AdvisoryProviderInterface
{
    /** @var list<list<string>> the package names of every getSecurityAdvisories() call */
    private array $queries = [];

    /**
     * @param array<string, list<PartialSecurityAdvisory>> $advisories keyed by package name as the repository spells it
     */
    public function __construct(
        private readonly string $name,
        private readonly array $advisories = [],
        private readonly bool $providesAdvisories = true,
        private readonly ?\Throwable $failure = null,
    ) {
        parent::__construct();
    }

    public function getRepoName(): string
    {
        return $this->name;
    }

    public function hasSecurityAdvisories(): bool
    {
        return $this->providesAdvisories;
    }

    public function getSecurityAdvisories(array $packageConstraintMap, bool $allowPartialAdvisories = false): array
    {
        $names = array_map('strval', array_keys($packageConstraintMap));
        $this->queries[] = $names;
        if ($this->failure !== null) {
            throw $this->failure;
        }
        $found = [];
        $advisories = [];
        foreach ($this->advisories as $package => $list) {
            if (in_array(strtolower($package), array_map('strtolower', $names), true)) {
                $found[] = $package;
                $advisories[$package] = $list;
            }
        }

        // Partial advisories are returned regardless of the flag; the adapter under test must cope.
        return ['namesFound' => $found, 'advisories' => $advisories];
    }

    /** @return list<list<string>> */
    public function queries(): array
    {
        return $this->queries;
    }
}
