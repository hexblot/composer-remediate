<?php

declare(strict_types=1);

namespace Remediate\Engine\Graph;

final class PathSegment
{
    public function __construct(
        public readonly string $packageName,
        public readonly string $prettyVersion,
        public readonly string $requiresConstraint,
        public readonly bool $isRoot,
    ) {
    }
}
