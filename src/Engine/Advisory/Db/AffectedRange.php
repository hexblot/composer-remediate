<?php

declare(strict_types=1);

namespace Remediate\Engine\Advisory\Db;

/** One source's statement about which versions of a package an advisory affects. */
final class AffectedRange
{
    public function __construct(
        public readonly string $package,
        public readonly string $constraint,
        public readonly string $source,
    ) {
    }
}
