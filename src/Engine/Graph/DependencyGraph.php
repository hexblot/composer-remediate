<?php

declare(strict_types=1);

namespace Remediate\Engine\Graph;

use Composer\Package\Link;
use Composer\Package\PackageInterface;
use Composer\Package\RootPackageInterface;
use Composer\Repository\InstalledRepository;
use Composer\Repository\RepositoryInterface;
use Composer\Repository\RootPackageRepository;

/**
 * Dependency paths over a lock snapshot, computed with the same InstalledRepository::getDependents()
 * walk that powers `composer why -r -t`.
 */
final class DependencyGraph
{
    public const MAX_PATHS = 200;
    public const MAX_DEPTH = 30;

    private InstalledRepository $repository;

    /** @var array<string, list<array{PackageInterface, Link}>> direct dependents, computed once per package */
    private array $dependents = [];

    /**
     * @param RepositoryInterface $locked the locked packages, typically Locker::getLockedRepository(true)
     */
    public function __construct(
        private readonly RootPackageInterface $root,
        RepositoryInterface $locked,
    ) {
        $this->repository = new InstalledRepository([
            new RootPackageRepository($root),
            $locked,
        ]);
    }

    /**
     * @return list<DependencyPath>
     */
    public function pathsToRoot(string $packageName): array
    {
        $paths = [];
        $this->walkFrom(strtolower($packageName), [], $paths, 0);

        // Cycles and orphans only matter when nothing reaches the root at all.
        $rooted = array_values(array_filter($paths, static fn (DependencyPath $p): bool => $p->reachesRoot()));

        return $rooted !== [] ? $rooted : $paths;
    }

    /**
     * The packages that depend on this one, directly, computed once per package.
     *
     * Eighth adversarial review, finding 10. This used to be one call asking Composer to expand the
     * entire recursive ancestor tree, with MAX_PATHS and MAX_DEPTH applied to the result afterwards.
     * The limits therefore bounded what was returned and not the work done to return it: a layered
     * graph of 35 packages cost six seconds and 144 MiB to produce the same 200 paths that 17 packages
     * produced in 0.007. Expanding one level at a time, and remembering each level, means a limit stops
     * the search rather than trimming its output.
     *
     * @return list<array{PackageInterface, Link}>
     */
    private function dependentsOf(string $name): array
    {
        if (isset($this->dependents[$name])) {
            return $this->dependents[$name];
        }
        $direct = [];
        foreach ($this->repository->getDependents($name, null, false, false) as $entry) {
            if (!is_array($entry) || !isset($entry[0], $entry[1]) || !$entry[0] instanceof PackageInterface || !$entry[1] instanceof Link) {
                continue;
            }
            $direct[] = [$entry[0], $entry[1]];
        }

        return $this->dependents[$name] = $direct;
    }

    /**
     * @param list<PathSegment>    $trail
     * @param list<DependencyPath> $paths
     */
    private function walkFrom(string $name, array $trail, array &$paths, int $depth): void
    {
        foreach ($this->dependentsOf($name) as [$package, $link]) {
            if (count($paths) >= self::MAX_PATHS) {
                return;
            }
            // getDependents() lists a package as its own dependent when it replaces something it also
            // requires (laravel/framework replacing illuminate/*); never repeat a package on a path.
            foreach ($trail as $seen) {
                if ($seen->packageName === $package->getName()) {
                    continue 2;
                }
            }
            $segment = new PathSegment(
                $package->getName(),
                $package->getPrettyVersion(),
                $link->getPrettyConstraint(),
                $package instanceof RootPackageInterface,
            );
            $newTrail = [...$trail, $segment];

            if ($segment->isRoot || $depth >= self::MAX_DEPTH) {
                $paths[] = new DependencyPath($newTrail);
                continue;
            }
            $parents = $this->dependentsOf($package->getName());
            if ($parents === []) {
                $paths[] = new DependencyPath($newTrail);
                continue;
            }
            $onward = false;
            foreach ($parents as [$parent]) {
                $repeats = false;
                foreach ($newTrail as $seen) {
                    if ($seen->packageName === $parent->getName()) {
                        $repeats = true;
                        break;
                    }
                }
                if (!$repeats) {
                    $onward = true;
                    break;
                }
            }
            if (!$onward) {
                // Every way up from here is a package already on this path: a cycle, not a dead end.
                $paths[] = new DependencyPath($newTrail, true);
                continue;
            }
            $this->walkFrom($package->getName(), $newTrail, $paths, $depth + 1);
        }
    }

    public function isRootRequirement(string $name): bool
    {
        $name = strtolower($name);

        return isset($this->root->getRequires()[$name]) || isset($this->root->getDevRequires()[$name]);
    }

    /**
     * Root-required ancestors across all paths, ordered by the shortest distance at which they appear.
     *
     * @param list<DependencyPath> $paths
     *
     * @return list<string>
     */
    public function nearestRootRequirements(array $paths): array
    {
        $distance = [];
        foreach ($paths as $path) {
            foreach ($path->segments as $index => $segment) {
                if ($segment->isRoot || !$this->isRootRequirement($segment->packageName)) {
                    continue;
                }
                $distance[$segment->packageName] = min($distance[$segment->packageName] ?? PHP_INT_MAX, $index);
            }
        }
        asort($distance);

        return array_keys($distance);
    }
}
