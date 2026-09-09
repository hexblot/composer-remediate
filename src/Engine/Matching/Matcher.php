<?php

declare(strict_types=1);

namespace Remediate\Engine\Matching;

use Composer\Package\PackageInterface;
use Remediate\Engine\Advisory\AdvisoryProvider;
use Remediate\Engine\Lock\LockSnapshot;

/**
 * Matches locked packages against advisories. Unlike Composer's auditor it also checks packages
 * that a locked package *replaces*, so monorepo builds (symfony/symfony, laravel/framework's
 * illuminate/* components) are caught.
 */
final class Matcher
{
    public function __construct(private readonly AdvisoryProvider $provider)
    {
    }

    /**
     * @param callable(string): bool $isRootRequirement
     *
     * @return list<Finding>
     */
    public function match(LockSnapshot $lock, callable $isRootRequirement): array
    {
        $advisories = $this->provider->advisoriesFor(self::namesToQuery($lock));
        $findings = [];

        foreach ($lock->packages as $package) {
            $name = $package->getName();
            foreach ($advisories[$name] ?? [] as $advisory) {
                if ($advisory->affectsVersion($package->getVersion())) {
                    $findings[] = new Finding($advisory, $name, $package->getVersion(), $package->getPrettyVersion(), $lock->isDev($name), $isRootRequirement($name));
                }
            }
            foreach ($package->getReplaces() as $target => $link) {
                $target = strtolower((string) $target);
                if ($lock->has($target)) {
                    continue; // the replaced package is also installed on its own; it is matched directly
                }
                foreach ($advisories[$target] ?? [] as $advisory) {
                    if ($advisory->affectsConstraint($link->getConstraint())) {
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

    /** @return list<string> */
    private static function namesToQuery(LockSnapshot $lock): array
    {
        $names = [];
        foreach ($lock->packages as $package) {
            $names[$package->getName()] = true;
            foreach (array_keys($package->getReplaces()) as $replaced) {
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
