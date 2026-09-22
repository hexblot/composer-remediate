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
        $results = $this->repository->getDependents(strtolower($packageName), null, false, true);
        $paths = [];
        $this->walk($results, [], $paths, 0);

        // Cycles and orphans only matter when nothing reaches the root at all.
        $rooted = array_values(array_filter($paths, static fn (DependencyPath $p): bool => $p->reachesRoot()));

        return $rooted !== [] ? $rooted : $paths;
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

    /**
     * @param array<mixed>      $results   nested [PackageInterface, Link, children|false] triples
     * @param list<PathSegment> $trail
     * @param list<DependencyPath> $paths
     */
    private function walk(array $results, array $trail, array &$paths, int $depth): void
    {
        foreach ($results as $entry) {
            if (count($paths) >= self::MAX_PATHS) {
                return;
            }
            if (!is_array($entry) || !isset($entry[0], $entry[1]) || !$entry[0] instanceof PackageInterface || !$entry[1] instanceof Link) {
                continue;
            }
            $package = $entry[0];
            $link = $entry[1];
            $children = $entry[2] ?? [];
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
            if ($children === false) {
                $paths[] = new DependencyPath($newTrail, true);
                continue;
            }
            if (!is_array($children) || $children === []) {
                $paths[] = new DependencyPath($newTrail);
                continue;
            }
            $this->walk($children, $newTrail, $paths, $depth + 1);
        }
    }
}
