<?php

declare(strict_types=1);

namespace Remediate\Output;

use Composer\Semver\Comparator;
use Composer\Semver\Constraint\Constraint;
use Composer\Semver\Interval;
use Composer\Semver\Intervals;
use Composer\Semver\VersionParser;
use Remediate\Engine\Candidate\Candidate;
use Remediate\Engine\Candidate\FixedRangeResolver;

/**
 * The persistent form of a `--with` constraint: the `conflict` entry for composer.json that keeps a
 * later update from falling back below the fix.
 *
 * A `--with` constraint lives for exactly one command. Nothing in the lock file records why the
 * version went up, so a later `composer update` is free to resolve back into the affected range. A
 * `conflict` entry says it once and for good, and makes the resolver name it when something tries.
 * Composer has no subcommand that writes one, so it is shown as an edit rather than folded into the
 * verified command.
 */
final class ConflictEntry
{
    /**
     * Every conflict entry a candidate's temporary constraints imply, package => constraint, ordered
     * by package name. Packages whose constraint has no lower bound to invert are left out.
     *
     * @return array<string, string>
     */
    public static function forCandidate(Candidate $candidate): array
    {
        $entries = [];
        foreach ($candidate->effectiveTemporaryConstraints() as $package => $constraint) {
            $entry = self::forConstraint($constraint);
            if ($entry !== null) {
                $entries[$package] = $entry;
            }
        }
        ksort($entries);

        return $entries;
    }

    /**
     * Inverts the lower bound of a fixed range: ">=3.14.0" becomes "<3.14.0", ">1.2.3" becomes
     * "<=1.2.3", and a multi-branch range is cut at its lowest start, which is the version the fix
     * must not fall below. Null when the constraint is unparseable or reaches down to zero, where
     * there is nothing below the fix to exclude.
     */
    public static function forConstraint(string $constraint): ?string
    {
        try {
            $parsed = (new VersionParser())->parseConstraints($constraint);
        } catch (\UnexpectedValueException) {
            return null;
        }

        $lowest = null;
        foreach (Intervals::get($parsed)['numeric'] as $interval) {
            $start = $interval->getStart();
            if ($lowest === null || Comparator::lessThan($start->getVersion(), $lowest->getVersion())) {
                $lowest = $start;
            }
        }
        if ($lowest === null || $lowest->getVersion() === Interval::fromZero()->getVersion()) {
            return null;
        }

        $operator = match ($lowest->getOperator()) {
            Constraint::STR_OP_GE => Constraint::STR_OP_LT,
            Constraint::STR_OP_GT => Constraint::STR_OP_LE,
            default => null,
        };
        if ($operator === null) {
            return null;
        }

        return FixedRangeResolver::pretty(new Constraint($operator, $lowest->getVersion()));
    }

    /**
     * The entries as they are written in composer.json, one `"package": "constraint"` line each.
     *
     * @param array<string, string> $entries
     *
     * @return list<string>
     */
    public static function asJsonLines(array $entries): array
    {
        $lines = [];
        foreach ($entries as $package => $constraint) {
            $lines[] = sprintf('"%s": "%s"', $package, $constraint);
        }

        return $lines;
    }
}
