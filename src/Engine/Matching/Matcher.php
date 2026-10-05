<?php

declare(strict_types=1);

namespace Remediate\Engine\Matching;

use Composer\Package\PackageInterface;
use Composer\Semver\Constraint\Constraint;
use Composer\Semver\Constraint\ConstraintInterface;
use Remediate\Engine\Advisory\Advisory;
use Remediate\Engine\Advisory\AdvisoryProvider;
use Remediate\Engine\Lock\LockSnapshot;

/**
 * Matches locked packages against advisories. Unlike Composer's auditor it also checks packages
 * that a locked package *replaces*, so monorepo builds (symfony/symfony, laravel/framework's
 * illuminate/* components) are caught.
 */
final class Matcher
{
    private IgnorePolicy $ignore;

    private int $ignoredCount = 0;

    public function __construct(private readonly AdvisoryProvider $provider)
    {
        $this->ignore = IgnorePolicy::none();
    }

    /**
     * @param list<string> $ids advisory ids (PKSA-…, GHSA-…) or CVEs, case-insensitive
     */
    public function withIgnored(array $ids): self
    {
        return $this->withIgnorePolicy($this->ignore->withIds($ids));
    }

    public function withIgnorePolicy(IgnorePolicy $policy): self
    {
        $clone = clone $this;
        $clone->ignore = $policy;

        return $clone;
    }

    /** @var array<string, true> ignore entries that suppressed at least one match in the last match() call */
    private array $usedIgnores = [];

    /** Number of advisory matches suppressed by the ignore list during the last match() call. */
    public function ignoredCount(): int
    {
        return $this->ignoredCount;
    }

    /**
     * Ignore entries that matched nothing in the last match() call: stale configuration worth cleaning up.
     *
     * @return list<string>
     */
    public function unusedIgnores(): array
    {
        return array_values(array_diff($this->ignore->entries(), array_keys($this->usedIgnores)));
    }

    /**
     * Whether a finding is ignored, given every name it can be addressed by: the locked package at its
     * version and, for a finding reached through `replace` or `provide`, the replaced package at the
     * range the link declares. An ignore written against either name applies, and every rule that
     * matches is recorded as used, so the hygiene report cannot call a rule that worked unused.
     *
     * @param list<array{string, ConstraintInterface}> $installed [package name, the versions it is present at]
     */
    private function isIgnored(Advisory $advisory, array $installed): bool
    {
        $ignored = false;
        foreach ($installed as [$packageName, $at]) {
            $entry = $this->ignore->matchedEntryAt($advisory->id, $advisory->cve, $packageName, $at);
            if ($entry !== null) {
                $this->usedIgnores[$entry] = true;
                $ignored = true;
            }
        }
        if ($ignored) {
            ++$this->ignoredCount;
        }

        return $ignored;
    }

    /**
     * @param callable(string): bool $isRootRequirement
     *
     * @return list<Finding>
     */
    public function match(LockSnapshot $lock, callable $isRootRequirement): array
    {
        $advisories = $this->provider->advisoriesFor(self::queriedNames($lock));
        $findings = [];
        $this->ignoredCount = 0;
        $this->usedIgnores = [];

        foreach ($lock->packages as $package) {
            $name = $package->getName();
            $installedAt = new Constraint('==', $package->getVersion());
            foreach ($advisories[$name] ?? [] as $advisory) {
                if ($advisory->affectsVersion($package->getVersion()) && !$this->isIgnored($advisory, [[$name, $installedAt]])) {
                    $findings[] = new Finding($advisory, $name, $package->getVersion(), $package->getPrettyVersion(), $lock->isDev($name), $isRootRequirement($name));
                }
            }
            // A package that replaces or provides another one is answerable for that package's advisories,
            // and an ignore written against the replaced name (the one the advisory is about) applies.
            foreach ($package->getReplaces() + $package->getProvides() as $target => $link) {
                $target = strtolower((string) $target);
                if ($lock->has($target)) {
                    continue; // the replaced package is also installed on its own; it is matched directly
                }
                foreach ($advisories[$target] ?? [] as $advisory) {
                    if ($advisory->affectsConstraint($link->getConstraint()) && !$this->isIgnored($advisory, [[$target, $link->getConstraint()], [$name, $installedAt]])) {
                        $findings[] = new Finding($advisory, $name, $package->getVersion(), $package->getPrettyVersion(), $lock->isDev($name), $isRootRequirement($name), $target);
                    }
                }
            }
        }

        $unique = [];
        foreach ($findings as $finding) {
            $unique[$finding->key()] ??= $finding;
        }
        ksort($unique);

        return array_values($unique);
    }

    /**
     * Keys (advisory@package) of every finding in a snapshot; used to verify candidate locks.
     *
     * @return array<string, true>
     */
    public function findingKeys(LockSnapshot $lock): array
    {
        $keys = [];
        foreach ($this->match($lock, static fn (): bool => false) as $finding) {
            $keys[$finding->key()] = true;
        }

        return $keys;
    }

    /**
     * Every name an advisory can be about in this lock: the locked packages plus everything they
     * replace or provide. Coverage questions must use the same set, or a gap in a replaced package
     * (symfony/http-foundation under symfony/symfony) goes unreported.
     *
     * @return list<string>
     */
    public static function queriedNames(LockSnapshot $lock): array
    {
        $names = [];
        foreach ($lock->packages as $package) {
            $names[$package->getName()] = true;
            foreach (array_keys($package->getReplaces() + $package->getProvides()) as $replaced) {
                $names[strtolower((string) $replaced)] = true;
            }
        }

        return array_keys($names);
    }

    /** @internal exposed for tests */
    public static function describePackage(PackageInterface $package): string
    {
        return $package->getName() . ' ' . $package->getPrettyVersion();
    }
}
