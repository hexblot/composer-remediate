<?php

declare(strict_types=1);

namespace Remediate\Engine\Advisory\Db;

/**
 * Source-neutral advisory record. Before merging, one instance represents one upstream record;
 * after merging, one instance represents one logical advisory with every source's ranges kept.
 */
final class NormalizedAdvisory
{
    /**
     * @param list<string>        $aliases  every identifier known for this advisory (CVE, GHSA, PKSA, file paths), including the canonical id
     * @param list<AffectedRange> $affected
     * @param list<SourceRecord>  $sources
     * @param list<string>        $conflicts packages for which sources disagree on the affected range
     */
    public function __construct(
        public readonly string $canonicalId,
        public readonly array $aliases,
        public readonly ?string $title,
        public readonly ?string $link,
        public readonly ?string $severity,
        public readonly ?\DateTimeImmutable $reportedAt,
        public readonly ?\DateTimeImmutable $withdrawnAt,
        public readonly array $affected,
        public readonly array $sources,
        public readonly array $conflicts = [],
    ) {
    }

    public function cve(): ?string
    {
        foreach ($this->aliases as $alias) {
            if (preg_match('{^CVE-\d{4}-\d+$}i', $alias) === 1) {
                return strtoupper($alias);
            }
        }

        return null;
    }

    /** @return list<string> distinct lower-case package names */
    public function packages(): array
    {
        $names = [];
        foreach ($this->affected as $range) {
            $names[strtolower($range->package)] = true;
        }

        return array_keys($names);
    }

    /**
     * Canonical identifier preference: CVE, then GHSA, then Packagist's PKSA, then anything else.
     */
    public static function rankId(string $id): int
    {
        return match (true) {
            preg_match('{^CVE-}i', $id) === 1 => 0,
            preg_match('{^GHSA-}i', $id) === 1 => 1,
            preg_match('{^PKSA-}i', $id) === 1 => 2,
            default => 3,
        };
    }
}
