<?php

declare(strict_types=1);

namespace Remediate\Engine\Advisory\Db;

/**
 * Groups upstream records that share any identifier (CVE, GHSA, PKSA, FriendsOfPHP file path) into
 * one logical advisory. Only exact alias matches merge: false deduplication is worse than
 * duplication. Every source's affected range is kept, and packages on which sources disagree are
 * flagged as conflicts.
 */
final class Merger
{
    public function __construct(private readonly RangeNormalizer $ranges = new RangeNormalizer())
    {
    }

    /**
     * @param list<NormalizedAdvisory> $records
     *
     * @return list<NormalizedAdvisory> merged advisories sorted by canonical id
     */
    public function merge(array $records): array
    {
        // union-find over alias keys
        $parent = [];
        $find = static function (string $x) use (&$parent): string {
            while (($parent[$x] ?? $x) !== $x) {
                $parent[$x] = $parent[$parent[$x]] ?? $parent[$x];
                $x = $parent[$x];
            }

            return $x;
        };
        $union = static function (string $a, string $b) use (&$parent, $find): void {
            $ra = $find($a);
            $rb = $find($b);
            if ($ra !== $rb) {
                $parent[$rb] = $ra;
            }
        };
        foreach ($records as $index => $record) {
            $keys = self::keys($record);
            $parent["#$index"] ??= "#$index";
            foreach ($keys as $key) {
                $parent[$key] ??= $key;
                $union("#$index", $key);
            }
        }

        $groups = [];
        foreach ($records as $index => $record) {
            $groups[$find("#$index")][] = $record;
        }

        $merged = array_map([$this, 'mergeGroup'], array_values($groups));
        usort($merged, static fn (NormalizedAdvisory $a, NormalizedAdvisory $b): int => strcmp($a->canonicalId, $b->canonicalId));

        return $merged;
    }

    /** @return list<string> */
    private static function keys(NormalizedAdvisory $record): array
    {
        $keys = [];
        foreach ($record->aliases as $alias) {
            $alias = strtolower(trim($alias));
            if ($alias !== '') {
                $keys[$alias] = true;
            }
        }

        return array_keys($keys);
    }

    /**
     * @param list<NormalizedAdvisory> $group
     */
    private function mergeGroup(array $group): NormalizedAdvisory
    {
        if (count($group) === 1) {
            return $group[0];
        }
        $aliases = [];
        $affected = [];
        $sources = [];
        $title = null;
        $link = null;
        $severity = null;
        $reportedAt = null;
        $allWithdrawn = true;
        $withdrawnAt = null;
        foreach ($group as $record) {
            foreach ($record->aliases as $alias) {
                $aliases[strtolower($alias)] = $alias;
            }
            array_push($affected, ...$record->affected);
            array_push($sources, ...$record->sources);
            $title ??= $record->title;
            $link ??= $record->link;
            $severity = self::higherSeverity($severity, $record->severity);
            if ($record->reportedAt !== null && ($reportedAt === null || $record->reportedAt < $reportedAt)) {
                $reportedAt = $record->reportedAt;
            }
            if ($record->withdrawnAt === null) {
                $allWithdrawn = false;
            } else {
                $withdrawnAt ??= $record->withdrawnAt;
            }
        }
        $ids = array_values($aliases);
        usort($ids, static fn (string $a, string $b): int => [NormalizedAdvisory::rankId($a), $a] <=> [NormalizedAdvisory::rankId($b), $b]);

        // conflicts: same package, semantically different ranges between sources
        $byPackage = [];
        foreach ($affected as $range) {
            $byPackage[strtolower($range->package)][$this->ranges->fingerprint($range->constraint)] = true;
        }
        $conflicts = array_keys(array_filter($byPackage, static fn (array $expressions): bool => count($expressions) > 1));

        return new NormalizedAdvisory($ids[0], $ids, $title, $link, $severity, $reportedAt, $allWithdrawn ? $withdrawnAt : null, $affected, $sources, $conflicts);
    }

    private static function higherSeverity(?string $a, ?string $b): ?string
    {
        $rank = ['critical' => 4, 'high' => 3, 'medium' => 2, 'moderate' => 2, 'low' => 1];
        $ra = $a === null ? -1 : ($rank[strtolower($a)] ?? 0);
        $rb = $b === null ? -1 : ($rank[strtolower($b)] ?? 0);

        return $rb > $ra ? $b : $a;
    }
}
