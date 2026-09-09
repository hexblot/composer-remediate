<?php

declare(strict_types=1);

namespace Remediate\Engine\Matching;

use Remediate\Engine\Advisory\Advisory;
use Remediate\Engine\Graph\DependencyPath;

final class Finding
{
    /**
     * @param list<DependencyPath> $paths
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
    ) {
    }

    /** Stable identity of "this advisory on this package", used to compare locks before and after. */
    public function key(): string
    {
        return $this->advisory->id . '@' . $this->packageName;
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
        );
    }
}
