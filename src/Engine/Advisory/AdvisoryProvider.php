<?php

declare(strict_types=1);

namespace Remediate\Engine\Advisory;

interface AdvisoryProvider
{
    /**
     * Returns every known advisory for the given package names, regardless of version, so the
     * caller can match the current lock and later re-match a candidate lock without a new lookup.
     *
     * @param list<string> $packageNames
     *
     * @return array<string, list<Advisory>> keyed by lower-case package name; names without advisories may be absent
     *
     * @throws AdvisoryLookupFailed
     */
    public function advisoriesFor(array $packageNames): array;

    /** Short human-readable description of the data source, for reports. */
    public function describe(): string;

    /**
     * Whether advisoriesFor() returns advisories for all versions of a package (true) or only those
     * matching the current lock (false). Incomplete providers weaken candidate validation.
     */
    public function isComplete(): bool;
}
