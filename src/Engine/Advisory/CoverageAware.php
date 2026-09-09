<?php

declare(strict_types=1);

namespace Remediate\Engine\Advisory;

/**
 * An advisory provider that knows where its own coverage is incomplete: records it holds about a
 * package that could not be interpreted, so the package may be affected by an advisory the provider
 * cannot express. The planner turns these into report warnings so a clean result is never presented
 * as cleaner than the data behind it.
 */
interface CoverageAware
{
    /**
     * @param list<string> $packageNames
     *
     * @return list<string> human-readable coverage warnings for the given packages
     */
    public function coverageWarnings(array $packageNames): array;
}
