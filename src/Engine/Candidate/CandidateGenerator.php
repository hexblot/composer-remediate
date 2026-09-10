<?php

declare(strict_types=1);

namespace Remediate\Engine\Candidate;

use Composer\DependencyResolver\Request;
use Composer\Package\Link;
use Composer\Semver\Constraint\ConstraintInterface;
use Composer\Semver\Interval;
use Composer\Semver\Intervals;
use Remediate\Engine\Graph\DependencyGraph;
use Remediate\Engine\Matching\Finding;

/**
 * Produces candidate commands for one finding, least invasive first. Every candidate is later
 * validated by the solver, so this class only has to be plausible, not right.
 */
final class CandidateGenerator
{
    public const MAX_PARENT_CANDIDATES = 6;

    /**
     * @param list<string> $extraArguments arguments every candidate must carry (e.g. --ignore-platform-req=php)
     */
    public function __construct(
        private readonly FixedRangeResolver $ranges = new FixedRangeResolver(),
        private readonly bool $allowDirectRequire = false,
        private readonly array $extraArguments = [],
    ) {
    }

    /**
     * @param array<string, Link>      $rootRequirements
     * @param ConstraintInterface|null $affected         affected range to escape; defaults to the finding's advisory,
     *                                                   callers pass the union when several advisories hit one package
     *
     * @return list<Candidate> empty when no fixed version newer than the locked one can exist
     */
    public function generate(Finding $finding, DependencyGraph $graph, array $rootRequirements, ?ConstraintInterface $affected = null): array
    {
        $fixed = $this->ranges->fixedRangeAbove($affected ?? $finding->advisory->affectedVersions, $finding->version);
        if ($fixed === null) {
            return [];
        }
        $with = [$finding->packageName => $fixed->getPrettyString()];
        $ancestors = $graph->nearestRootRequirements($finding->paths);
        if ($finding->isRootRequirement) {
            $ancestors = array_values(array_unique([$finding->packageName, ...$ancestors]));
        }

        $candidates = [
            ...self::ownCandidates($finding->packageName, $with),
            ...self::parentCandidates($finding->packageName, $ancestors, $this->nearestPerPath($finding, $graph), $with),
            ...$this->widenCandidates($ancestors, $rootRequirements, $with),
        ];
        if ($this->allowDirectRequire && !$finding->isRootRequirement) {
            $candidates[] = new Candidate(
                Strategy::DirectRequire,
                [$finding->packageName],
                Request::UPDATE_LISTED_WITH_TRANSITIVE_DEPS,
                [],
                true,
                [$finding->packageName => new RootConstraintChange($finding->packageName, null, $fixed->getPrettyString(), $finding->isDev)],
                sprintf('require %s %s directly to force the fixed version', $finding->packageName, $fixed->getPrettyString()),
            );
        }
        if ($this->extraArguments !== []) {
            $candidates = array_map(fn (Candidate $c): Candidate => $c->withExtraArguments($this->extraArguments), $candidates);
        }

        return $candidates;
    }

    /**
     * Updating the vulnerable package itself: alone (a stale lock), then with its own dependencies
     * and a constraint forcing a fixed version.
     *
     * @param array<string, string> $with
     *
     * @return list<Candidate>
     */
    private static function ownCandidates(string $package, array $with): array
    {
        return [
            new Candidate(
                Strategy::LockRefresh,
                [$package],
                Request::UPDATE_ONLY_LISTED,
                [],
                false,
                [],
                sprintf('update %s alone; works when the lock file is merely stale', $package),
            ),
            new Candidate(
                Strategy::WithDependencies,
                [$package],
                Request::UPDATE_LISTED_WITH_TRANSITIVE_DEPS_NO_ROOT_REQUIRE,
                $with,
                true,
                [],
                sprintf('update %s and its own dependencies, forcing a fixed version', $package),
            ),
        ];
    }

    /**
     * Updating the root requirements that lead to the vulnerable package, one at a time up to
     * MAX_PARENT_CANDIDATES, then every nearest parent at once when several paths exist.
     *
     * @param list<string>          $ancestors
     * @param list<string>          $nearestPerPath
     * @param array<string, string> $with
     *
     * @return list<Candidate>
     */
    private static function parentCandidates(string $package, array $ancestors, array $nearestPerPath, array $with): array
    {
        $candidates = [];
        foreach (array_slice($ancestors, 0, self::MAX_PARENT_CANDIDATES) as $ancestor) {
            $candidates[] = new Candidate(
                Strategy::ParentUpdate,
                [$ancestor],
                Request::UPDATE_LISTED_WITH_TRANSITIVE_DEPS,
                $with,
                true,
                [],
                sprintf('update %s with all of its dependencies, forcing a fixed %s', $ancestor, $package),
            );
        }
        if (count($nearestPerPath) > 1) {
            $candidates[] = new Candidate(
                Strategy::ParentUpdate,
                $nearestPerPath,
                Request::UPDATE_LISTED_WITH_TRANSITIVE_DEPS,
                $with,
                true,
                [],
                sprintf('update every parent that requires %s (%s)', $package, implode(', ', $nearestPerPath)),
            );
        }

        return $candidates;
    }

    /**
     * Widening the composer.json constraint of up to three ancestors to their next major, then
     * updating them with all dependencies.
     *
     * @param list<string>          $ancestors
     * @param array<string, Link>   $rootRequirements
     * @param array<string, string> $with
     *
     * @return list<Candidate>
     */
    private function widenCandidates(array $ancestors, array $rootRequirements, array $with): array
    {
        $candidates = [];
        foreach (array_slice($ancestors, 0, 3) as $ancestor) {
            $link = $rootRequirements[$ancestor] ?? null;
            if ($link === null) {
                continue;
            }
            $next = self::nextMajorConstraint($link->getConstraint());
            if ($next === null) {
                continue;
            }
            $candidates[] = new Candidate(
                Strategy::RootConstraintWiden,
                [$ancestor],
                Request::UPDATE_LISTED_WITH_TRANSITIVE_DEPS,
                $with,
                true,
                [$ancestor => new RootConstraintChange($ancestor, $link->getPrettyConstraint(), $next, $this->isDevLink($link))],
                sprintf('allow %s %s in composer.json, then update it with all dependencies', $ancestor, $next),
            );
        }

        return $candidates;
    }

    /**
     * The nearest root-required ancestor of each distinct path, deduplicated.
     *
     * @return list<string>
     */
    private function nearestPerPath(Finding $finding, DependencyGraph $graph): array
    {
        $nearest = [];
        foreach ($finding->paths as $path) {
            $ancestors = $path->rootRequiredAncestors(fn (string $name): bool => $graph->isRootRequirement($name));
            if ($ancestors !== []) {
                $nearest[$ancestors[0]] = true;
            }
        }
        if ($finding->isRootRequirement) {
            $nearest[$finding->packageName] = true;
        }

        return array_keys($nearest);
    }

    /**
     * The smallest caret constraint starting at the current upper bound:
     * ^11.4 => ^12.0, ~2.3.0 => ^2.4, ^0.5 => ^0.6; null when there is no upper bound (>=1, *).
     */
    public static function nextMajorConstraint(ConstraintInterface $constraint): ?string
    {
        $intervals = Intervals::get($constraint)['numeric'];
        if ($intervals === []) {
            return null;
        }
        $infinity = Interval::untilPositiveInfinity()->getVersion();
        $upper = null;
        foreach ($intervals as $interval) {
            $end = $interval->getEnd()->getVersion();
            if ($end === $infinity) {
                return null;
            }
            $upper = $end;
        }
        if ($upper === null) {
            return null;
        }
        $numeric = explode('-', $upper)[0];
        $parts = array_map('intval', explode('.', $numeric));
        return sprintf('^%d.%d', $parts[0] ?? 0, $parts[1] ?? 0);
    }

    private function isDevLink(Link $link): bool
    {
        return $link->getDescription() === Link::TYPE_DEV_REQUIRE;
    }
}
