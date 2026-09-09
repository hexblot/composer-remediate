<?php

declare(strict_types=1);

namespace Remediate\Engine\Candidate;

final class RootConstraintChange
{
    public function __construct(
        public readonly string $packageName,
        public readonly ?string $fromConstraint,
        public readonly string $toConstraint,
        public readonly bool $isDev,
    ) {
    }
}
