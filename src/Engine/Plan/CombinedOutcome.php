<?php

declare(strict_types=1);

namespace Remediate\Engine\Plan;

/** What came of one attempt in the global search for a command that fixes every finding. */
enum CombinedOutcome: string
{
    /** Resolves and fixes every finding. */
    case Accepted = 'accepted';
    /** Resolves but leaves some findings. */
    case Partial = 'partial';
    /** The solver found no solution. */
    case Unresolved = 'unresolved';
    /** Resolves but breaks an acceptance rule: new advisories, or a release younger than the cooldown. */
    case Rejected = 'rejected';
}
