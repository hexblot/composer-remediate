<?php

declare(strict_types=1);

namespace Remediate\Engine\Graph;

/**
 * One chain of "requires" links from the package immediately requiring the vulnerable package up
 * to the root package. Segments are ordered nearest-parent first.
 */
final class DependencyPath
{
    /**
     * @param list<PathSegment> $segments
     */
    public function __construct(
        public readonly array $segments,
        public readonly bool $cyclic = false,
    ) {
    }

    public function reachesRoot(): bool
    {
        $last = $this->segments[count($this->segments) - 1] ?? null;

        return $last !== null && $last->isRoot;
    }

    /**
     * Names of root-required packages on this path, nearest first, excluding the root itself.
     *
     * @param callable(string): bool $isRootRequirement
     *
     * @return list<string>
     */
    public function rootRequiredAncestors(callable $isRootRequirement): array
    {
        $result = [];
        foreach ($this->segments as $segment) {
            if (!$segment->isRoot && $isRootRequirement($segment->packageName)) {
                $result[] = $segment->packageName;
            }
        }

        return $result;
    }

    public function depth(): int
    {
        return count($this->segments);
    }
}
