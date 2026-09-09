<?php

declare(strict_types=1);

namespace Remediate\Engine\Lock;

use Composer\Package\AliasPackage;
use Composer\Package\Locker;
use Composer\Package\PackageInterface;

/**
 * Immutable view of a resolved dependency set: the packages of a lock file (or of a solver result)
 * keyed by name, with the require-dev flag preserved.
 */
final class LockSnapshot
{
    /**
     * @param array<string, PackageInterface> $packages
     * @param array<string, true>             $dev
     */
    private function __construct(
        public readonly array $packages,
        private readonly array $dev,
    ) {
    }

    public static function fromLocker(Locker $locker): self
    {
        $prod = $locker->getLockedRepository(false)->getPackages();
        $all = $locker->getLockedRepository(true)->getPackages();
        $prodNames = [];
        foreach ($prod as $package) {
            $prodNames[$package->getName()] = true;
        }
        $dev = [];
        foreach ($all as $package) {
            if (!isset($prodNames[$package->getName()])) {
                $dev[] = $package;
            }
        }

        return self::fromPackages($prod, $dev);
    }

    /**
     * @param iterable<PackageInterface> $prod
     * @param iterable<PackageInterface> $dev
     */
    public static function fromPackages(iterable $prod, iterable $dev): self
    {
        $packages = [];
        $devMap = [];
        foreach ($prod as $package) {
            if ($package instanceof AliasPackage) {
                continue;
            }
            $packages[$package->getName()] = $package;
        }
        foreach ($dev as $package) {
            if ($package instanceof AliasPackage) {
                continue;
            }
            $packages[$package->getName()] = $package;
            $devMap[$package->getName()] = true;
        }
        ksort($packages);

        return new self($packages, $devMap);
    }

    public function get(string $name): ?PackageInterface
    {
        return $this->packages[strtolower($name)] ?? null;
    }

    public function has(string $name): bool
    {
        return isset($this->packages[strtolower($name)]);
    }

    public function isDev(string $name): bool
    {
        return isset($this->dev[strtolower($name)]);
    }

    /** @return list<string> */
    public function names(): array
    {
        return array_keys($this->packages);
    }

    public function count(): int
    {
        return count($this->packages);
    }
}
