<?php

declare(strict_types=1);

namespace Remediate\Engine\Project;

use Composer\Composer;
use Composer\Factory;
use Composer\IO\IOInterface;
use Composer\Package\Link;
use Composer\Package\Locker;
use Composer\Package\RootPackageInterface;
use Composer\Repository\LockArrayRepository;
use Remediate\Engine\Lock\LockSnapshot;

/**
 * Everything the engine needs to know about the project under analysis, obtained from a live
 * Composer instance (plugin mode) or from a directory (tests, standalone use).
 */
final class ProjectContext
{
    private function __construct(
        public readonly Composer $composer,
        public readonly string $directory,
    ) {
    }

    public static function fromComposer(Composer $composer): self
    {
        $file = Factory::getComposerFile();
        $real = realpath($file);
        $directory = $real !== false ? dirname($real) : (string) getcwd();

        return new self($composer, $directory);
    }

    public static function fromDirectory(string $directory, IOInterface $io): self
    {
        $real = realpath($directory);
        if ($real === false || !is_file($real . '/composer.json')) {
            throw new \InvalidArgumentException(sprintf('%s does not contain a composer.json', $directory));
        }
        $composer = Factory::create($io, $real . '/composer.json', true, true);

        return new self($composer, $real);
    }

    public function rootPackage(): RootPackageInterface
    {
        return $this->composer->getPackage();
    }

    public function locker(): Locker
    {
        return $this->composer->getLocker();
    }

    public function isLocked(): bool
    {
        return $this->locker()->isLocked();
    }

    public function lockSnapshot(): LockSnapshot
    {
        return LockSnapshot::fromLocker($this->locker());
    }

    /** A fresh repository of all locked packages including require-dev. */
    public function lockedRepository(): LockArrayRepository
    {
        return $this->locker()->getLockedRepository(true);
    }

    /** @return array<string, Link> requires and dev requires of the root package, keyed by target name */
    public function rootRequirements(): array
    {
        $root = $this->rootPackage();

        return $root->getRequires() + $root->getDevRequires();
    }

    public function isRootRequirement(string $name): bool
    {
        return isset($this->rootRequirements()[strtolower($name)]);
    }

    public function isDevRequirement(string $name): bool
    {
        return isset($this->rootPackage()->getDevRequires()[strtolower($name)]);
    }

    public function composerJsonPath(): string
    {
        return $this->directory . '/composer.json';
    }

    public function lockPath(): string
    {
        return $this->directory . '/composer.lock';
    }

    public function authJsonPath(): ?string
    {
        $path = $this->directory . '/auth.json';

        return is_file($path) ? $path : null;
    }

    public function composerVersion(): string
    {
        return Composer::getVersion();
    }
}
