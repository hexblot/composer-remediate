<?php

declare(strict_types=1);

namespace Remediate\Engine\Solver;

use Composer\Package\PackageInterface;
use Remediate\Engine\Lock\LockSnapshot;

/**
 * Package-level difference between two lock snapshots: the blast radius of a candidate.
 */
final class LockDiff
{
    /**
     * @param list<PackageChange>     $changes
     * @param list<CapabilityChange>  $capabilityChanges what the update changes about what a package
     *                                                   can do, ordered by package name
     */
    private function __construct(
        public readonly array $changes,
        public readonly array $capabilityChanges = [],
    ) {
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
            // Same version, different commit: a moved dev branch or a re-tagged release. Either way the
            // installed code changes, so it is a change (of unclassifiable size) and the release-age
            // guard sees it like any other.
            $oldRef = $package->getSourceReference() ?? $package->getDistReference();
            $newRef = $new->getSourceReference() ?? $new->getDistReference();
            if ($oldRef !== null && $newRef !== null && $oldRef !== $newRef) {
                $changes[] = new PackageChange($name, PackageChange::CHANGED, $package->getPrettyVersion() . '#' . substr($oldRef, 0, 7), $new->getPrettyVersion() . '#' . substr($newRef, 0, 7), $package->getVersion(), $new->getVersion(), VersionStep::Other);
            }
        }
        foreach ($after->packages as $name => $package) {
            if (!$before->has($name)) {
                $changes[] = PackageChange::added($name, $package->getPrettyVersion(), $package->getVersion());
            }
        }
        usort($changes, static fn (PackageChange $a, PackageChange $b): int => strcmp($a->packageName, $b->packageName));

        return new self($changes, self::capabilities($before, $after, $changes));
    }

    /**
     * What each changed package gains or moves in terms of what it can do. Read from metadata the
     * snapshots already carry: nothing is downloaded and no archive is opened.
     *
     * A package that is only removed cannot gain anything, so removals are skipped. A package that
     * is added is reported only for the two capabilities that run code without being called, since
     * every new package brings its own everything and listing all of it would say nothing.
     *
     * @param list<PackageChange> $changes
     *
     * @return list<CapabilityChange>
     */
    private static function capabilities(LockSnapshot $before, LockSnapshot $after, array $changes): array
    {
        $capabilities = [];
        foreach ($changes as $change) {
            if ($change->kind === PackageChange::REMOVED) {
                continue;
            }
            $new = $after->get($change->packageName);
            if ($new === null) {
                continue;
            }
            $old = $change->kind === PackageChange::ADDED ? null : $before->get($change->packageName);
            array_push($capabilities, ...self::forPackage($change->packageName, $old, $new));
        }

        return $capabilities;
    }

    /** @return list<CapabilityChange> */
    private static function forPackage(string $name, ?PackageInterface $old, PackageInterface $new): array
    {
        $out = [];
        $newFiles = self::autoloadFiles($new);
        $newBinaries = self::binaries($new);

        if ($old === null) {
            // A package that was not there before: only what runs unasked is worth a line.
            if ($new->getType() === 'composer-plugin') {
                $out[] = new CapabilityChange($name, CapabilityKind::Type, null, $new->getType());
            }
            if ($newFiles !== '') {
                $out[] = new CapabilityChange($name, CapabilityKind::AutoloadFiles, null, $newFiles);
            }

            return $out;
        }

        if ($old->getType() !== $new->getType()) {
            $out[] = new CapabilityChange($name, CapabilityKind::Type, $old->getType(), $new->getType());
        }
        $oldFiles = self::autoloadFiles($old);
        if ($oldFiles !== $newFiles && $newFiles !== '') {
            $out[] = new CapabilityChange($name, CapabilityKind::AutoloadFiles, $oldFiles === '' ? null : $oldFiles, $newFiles);
        }
        $oldBinaries = self::binaries($old);
        if ($oldBinaries !== $newBinaries && $newBinaries !== '') {
            $out[] = new CapabilityChange($name, CapabilityKind::Binaries, $oldBinaries === '' ? null : $oldBinaries, $newBinaries);
        }
        $oldSource = self::host($old->getSourceUrl());
        $newSource = self::host($new->getSourceUrl());
        if ($oldSource !== $newSource && $newSource !== null) {
            $out[] = new CapabilityChange($name, CapabilityKind::SourceHost, $oldSource, $newSource);
        }
        $oldDist = self::host($old->getDistUrl());
        $newDist = self::host($new->getDistUrl());
        if ($oldDist !== $newDist && $newDist !== null) {
            $out[] = new CapabilityChange($name, CapabilityKind::DistHost, $oldDist, $newDist);
        }

        return $out;
    }

    /** The `autoload.files` entries as one comparable, printable string. */
    private static function autoloadFiles(PackageInterface $package): string
    {
        $files = $package->getAutoload()['files'] ?? [];
        if (!is_array($files)) {
            return '';
        }
        $files = array_values(array_filter($files, 'is_string'));
        sort($files);

        return implode(', ', $files);
    }

    private static function binaries(PackageInterface $package): string
    {
        $binaries = $package->getBinaries();
        sort($binaries);

        return implode(', ', $binaries);
    }

    /** The host a URL is served from, or null when there is no URL or it names no host. */
    private static function host(?string $url): ?string
    {
        if ($url === null || $url === '') {
            return null;
        }
        $host = parse_url($url, PHP_URL_HOST);

        return is_string($host) && $host !== '' ? $host : null;
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

    /** @return list<PackageChange> changes whose target is an alpha, beta, RC or dev version */
    public function prereleaseTargets(): array
    {
        return array_values(array_filter($this->changes, static fn (PackageChange $c): bool => $c->targetsPrerelease()));
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
            $total += $change->distance();
        }

        return $total;
    }

    /** @return list<CapabilityChange> the ones that let code run which could not run before */
    public function newCodeCapabilities(): array
    {
        return array_values(array_filter($this->capabilityChanges, static fn (CapabilityChange $c): bool => $c->runsNewCode()));
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
