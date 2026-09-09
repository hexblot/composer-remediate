<?php

declare(strict_types=1);

namespace Remediate\Engine\Solver;

use Remediate\Engine\Lock\LockSnapshot;

/**
 * Package-level difference between two lock snapshots: the blast radius of a candidate.
 */
final class LockDiff
{
    /**
     * @param list<PackageChange> $changes
     */
    private function __construct(public readonly array $changes)
    {
    }

    public static function between(LockSnapshot $before, LockSnapshot $after): self
    {
        $changes = [];
        foreach ($before->packages as $name => $package) {
            $new = $after->get($name);
            if ($new === null) {
                $changes[] = PackageChange::removed($name, $package->getPrettyVersion(), $package->getVersion());
                continue;
            }
            if ($new->getVersion() !== $package->getVersion()) {
                $changes[] = PackageChange::between($name, $package->getPrettyVersion(), $package->getVersion(), $new->getPrettyVersion(), $new->getVersion());
                continue;
            }
            $oldRef = $package->getSourceReference() ?? $package->getDistReference();
            $newRef = $new->getSourceReference() ?? $new->getDistReference();
            if ($oldRef !== null && $newRef !== null && $oldRef !== $newRef && str_starts_with($package->getVersion(), 'dev-')) {
                $changes[] = PackageChange::between($name, $package->getPrettyVersion() . '#' . substr($oldRef, 0, 7), $package->getVersion(), $new->getPrettyVersion() . '#' . substr($newRef, 0, 7), $new->getVersion());
            }
        }
        foreach ($after->packages as $name => $package) {
            if (!$before->has($name)) {
                $changes[] = PackageChange::added($name, $package->getPrettyVersion(), $package->getVersion());
            }
        }
        usort($changes, static fn (PackageChange $a, PackageChange $b): int => strcmp($a->packageName, $b->packageName));

        return new self($changes);
    }

    public function count(): int
    {
        return count($this->changes);
    }

    /** @return list<PackageChange> */
    public function added(): array
    {
        return array_values(array_filter($this->changes, static fn (PackageChange $c): bool => $c->kind === PackageChange::ADDED));
    }

    /** @return list<PackageChange> */
    public function removed(): array
    {
        return array_values(array_filter($this->changes, static fn (PackageChange $c): bool => $c->kind === PackageChange::REMOVED));
    }

    /** @return list<PackageChange> */
    public function versionChanges(): array
    {
        return array_values(array_filter($this->changes, static fn (PackageChange $c): bool => $c->isVersionChange()));
    }

    public function hasMajorChange(): bool
    {
        foreach ($this->changes as $change) {
            if ($change->step === VersionStep::Major) {
                return true;
            }
        }

        return false;
    }

    public function hasDowngrade(): bool
    {
        foreach ($this->changes as $change) {
            if ($change->kind === PackageChange::DOWNGRADED) {
                return true;
            }
        }

        return false;
    }

    /** @return list<string> */
    public function changedNames(): array
    {
        return array_map(static fn (PackageChange $c): string => $c->packageName, $this->changes);
    }

    public function versionDistance(): int
    {
        $total = 0;
        foreach ($this->changes as $change) {
            $total += $change->step?->weight() ?? VersionStep::Other->weight();
        }

        return $total;
    }

    public function changeFor(string $packageName): ?PackageChange
    {
        foreach ($this->changes as $change) {
            if ($change->packageName === strtolower($packageName)) {
                return $change;
            }
        }

        return null;
    }
}
