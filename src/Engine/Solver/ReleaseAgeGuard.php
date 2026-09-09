<?php

declare(strict_types=1);

namespace Remediate\Engine\Solver;

use Remediate\Engine\Lock\LockSnapshot;

/**
 * Supply-chain cooldown: a candidate that installs a release younger than the configured number of
 * days is rejected, so a freshly published (and possibly compromised or broken) version is never
 * recommended before it has had time to be looked at. Analogous to npm's minimum release age.
 * Releases without a known date are refused as well: the guard promises an age it cannot prove.
 */
final class ReleaseAgeGuard
{
    public function __construct(private readonly int $minAgeDays, private readonly \DateTimeImmutable $now = new \DateTimeImmutable('now', new \DateTimeZone('UTC')))
    {
    }

    /**
     * @return list<string> human-readable descriptions of the changes that are too young, empty when the candidate is acceptable
     */
    public function tooYoung(LockDiff $diff, LockSnapshot $after): array
    {
        if ($this->minAgeDays <= 0) {
            return [];
        }
        $cutoff = $this->now->modify(sprintf('-%d days', $this->minAgeDays));
        $young = [];
        foreach ($diff->changes as $change) {
            if ($change->kind === PackageChange::REMOVED) {
                continue;
            }
            $package = $after->get($change->packageName);
            $released = $package?->getReleaseDate();
            if ($released === null) {
                // No release date in the metadata: the cooldown cannot be proven, so the change is refused.
                $young[] = sprintf('%s %s (release date unknown)', $change->packageName, $change->toPretty ?? '?');
                continue;
            }
            if ($released > $cutoff) {
                $young[] = sprintf('%s %s (released %s, %d day%s ago)', $change->packageName, $change->toPretty ?? '?', $released->format('Y-m-d'), $ageDays = max(0, (int) $this->now->diff($released)->days), $ageDays === 1 ? '' : 's');
            }
        }

        return $young;
    }
}
