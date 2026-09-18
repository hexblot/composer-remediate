<?php

declare(strict_types=1);

namespace Remediate\Output;

use Remediate\Engine\Plan\Plan;

/**
 * Whether a run established what it set out to establish, in the one place every report format asks.
 *
 * Exit codes 0, 1 and 2 are complete runs: a lock with nothing in it, a lock with fixes, a lock with
 * a finding nothing could fix. Findings are the answer, not a failure. Exit codes 3, 4 and 5 are runs
 * that could not answer: a tool error, advisory data that could not be read, package metadata that
 * could not be fetched. The distinction matters because every machine-readable format has a place to
 * say "this did not complete", and an empty vulnerability list marked successful reads as clean.
 *
 * Every renderer takes its answer from here, so no format can call a run successful that another
 * calls failed.
 */
final class ScanOutcome
{
    public static function succeeded(Plan $plan): bool
    {
        return $plan->exitCode() < Plan::EXIT_ERROR;
    }

    /** Why the run did not complete, for formats that carry a message; empty when it did. */
    public static function failureMessage(Plan $plan): ?string
    {
        if (self::succeeded($plan)) {
            return null;
        }

        return match ($plan->exitCode()) {
            Plan::EXIT_ADVISORIES_UNAVAILABLE => 'Scan failed: advisory data unavailable or incomplete for this lock (exit 4); the vulnerability list is not a clean result.',
            Plan::EXIT_SOLVER_FAILURE => 'Scan failed: package metadata could not be fetched while verifying fixes (exit 5).',
            default => 'Scan failed: a tool or solver error left at least one outcome unknown (exit 3).',
        };
    }
}
