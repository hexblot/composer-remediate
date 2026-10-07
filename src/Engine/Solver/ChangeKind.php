<?php

declare(strict_types=1);

namespace Remediate\Engine\Solver;

/**
 * What a candidate lock did to one package. The backing values are what the JSON report prints as
 * `changes[].kind`, so they are part of the report contract and do not change.
 */
enum ChangeKind: string
{
    case Added = 'added';
    case Removed = 'removed';
    case Upgraded = 'upgraded';
    case Downgraded = 'downgraded';
    /** A move that is not a version step: a dev reference, or a version with no numeric parts to compare. */
    case Changed = 'changed';

    public function isVersionChange(): bool
    {
        return $this !== self::Added && $this !== self::Removed;
    }
}
