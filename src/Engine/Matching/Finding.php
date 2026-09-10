<?php

declare(strict_types=1);

namespace Remediate\Engine\Matching;

use Remediate\Engine\Advisory\Advisory;
use Remediate\Engine\Graph\DependencyPath;

final class Finding
{
    /**
     * @param list<DependencyPath>       $paths
     * @param array<string, string|null> $abandoned packages on the dependency paths (the vulnerable package included)
     *                                              that Packagist marks abandoned, with the suggested replacement when one is named
     */
    public function __construct(
        public readonly Advisory $advisory,
        public readonly string $packageName,
        public readonly string $version,
        public readonly string $prettyVersion,
        public readonly bool $isDev,
        public readonly bool $isRootRequirement,
        public readonly ?string $viaReplacedName = null,
        public readonly array $paths = [],
        public readonly array $abandoned = [],
    ) {
    }

    public function isAbandoned(): bool
    {
        return array_key_exists($this->packageName, $this->abandoned);
    }

    /**
     * Stable identity of "this advisory on this package", used to compare locks before and after and
     * as the baseline key. A finding reached through a replaced or provided package carries that
     * target too: one advisory id (a CVE spanning several components) on one replacing package would
     * otherwise collapse two findings into one.
     */
    public function key(): string
    {
        return $this->advisory->id . '@' . $this->packageName . ($this->viaReplacedName !== null ? '/' . $this->viaReplacedName : '');
    }

    /**
     * @param list<DependencyPath> $paths
     */
    public function withPaths(array $paths): self
    {
        return new self(
            $this->advisory,
            $this->packageName,
            $this->version,
            $this->prettyVersion,
            $this->isDev,
            $this->isRootRequirement,
            $this->viaReplacedName,
            $paths,
            $this->abandoned,
        );
    }

    /** @param array<string, string|null> $abandoned */
    public function withAbandoned(array $abandoned): self
    {
        return new self(
            $this->advisory,
            $this->packageName,
            $this->version,
            $this->prettyVersion,
            $this->isDev,
            $this->isRootRequirement,
            $this->viaReplacedName,
            $this->paths,
            $abandoned,
        );
    }
}
