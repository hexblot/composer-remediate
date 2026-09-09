<?php

declare(strict_types=1);

namespace Remediate\Engine\Candidate;

use Composer\Semver\Comparator;
use Composer\Semver\Constraint\Constraint;
use Composer\Semver\Constraint\ConstraintInterface;
use Composer\Semver\Constraint\MultiConstraint;
use Composer\Semver\Interval;
use Composer\Semver\Intervals;

/**
 * Derives the "fixed" range from an advisory's affected range: every version that is not affected
 * and is newer than the currently locked version. Downgrades are never proposed.
 */
final class FixedRangeResolver
{
    public function fixedRangeAbove(ConstraintInterface $affected, string $currentNormalized): ?ConstraintInterface
    {
        $intervals = Intervals::get($affected)['numeric'];
        usort($intervals, static fn (Interval $a, Interval $b): int => Comparator::lessThan($a->getStart()->getVersion(), $b->getStart()->getVersion()) ? -1 : (Comparator::greaterThan($a->getStart()->getVersion(), $b->getStart()->getVersion()) ? 1 : 0));

        $infinity = Interval::untilPositiveInfinity()->getVersion();
        $cursor = new Constraint(Constraint::STR_OP_GT, $currentNormalized);
        $pieces = [];
        $openEnded = true;

        foreach ($intervals as $interval) {
            $gapEnd = self::flip($interval->getStart());
            if (self::isNonEmpty($cursor, $gapEnd)) {
                $pieces[] = self::piece($cursor, $gapEnd);
            }
            if ($interval->getEnd()->getVersion() === $infinity) {
                $openEnded = false;
                break;
            }
            $cursor = self::laterStart($cursor, self::flip($interval->getEnd()));
        }

        if ($openEnded) {
            $pieces[] = self::piece($cursor, null);
        }

        if ($pieces === []) {
            return null;
        }

        $result = count($pieces) === 1 ? $pieces[0] : new MultiConstraint($pieces, false);
        $result->setPrettyString(implode(' || ', array_map(static fn (ConstraintInterface $c): string => $c->getPrettyString(), $pieces)));

        return $result;
    }

    /** Turns an interval bound into the bound of its complement: ">= x" becomes "< x", "< y" becomes ">= y". */
    private static function flip(Constraint $bound): Constraint
    {
        $operator = match ($bound->getOperator()) {
            Constraint::STR_OP_GE => Constraint::STR_OP_LT,
            Constraint::STR_OP_GT => Constraint::STR_OP_LE,
            Constraint::STR_OP_LT => Constraint::STR_OP_GE,
            Constraint::STR_OP_LE => Constraint::STR_OP_GT,
            default => throw new \LogicException('Unexpected interval bound operator ' . $bound->getOperator()),
        };

        return new Constraint($operator, $bound->getVersion());
    }

    private static function isNonEmpty(Constraint $start, Constraint $end): bool
    {
        if (Comparator::lessThan($start->getVersion(), $end->getVersion())) {
            return true;
        }
        if ($start->getVersion() === $end->getVersion()) {
            return $start->getOperator() === Constraint::STR_OP_GE && $end->getOperator() === Constraint::STR_OP_LE;
        }

        return false;
    }

    private static function laterStart(Constraint $a, Constraint $b): Constraint
    {
        if (Comparator::greaterThan($b->getVersion(), $a->getVersion())) {
            return $b;
        }
        if ($b->getVersion() === $a->getVersion() && $b->getOperator() === Constraint::STR_OP_GT) {
            return $b;
        }

        return $a;
    }

    private static function piece(Constraint $start, ?Constraint $end): ConstraintInterface
    {
        $startPretty = self::pretty($start);
        if ($end === null) {
            $c = new Constraint($start->getOperator(), $start->getVersion());
            $c->setPrettyString($startPretty);

            return $c;
        }
        $piece = new MultiConstraint([new Constraint($start->getOperator(), $start->getVersion()), new Constraint($end->getOperator(), $end->getVersion())], true);
        $piece->setPrettyString($startPretty . ',' . self::pretty($end));

        return $piece;
    }

    /**
     * Composer parses ">=X" as ">= X-dev" and "<X" as "< X-dev", so for those operators the "-dev"
     * suffix is dropped in the human form; the string re-parses to the identical constraint.
     */
    public static function pretty(Constraint $constraint): string
    {
        $version = self::shortVersion($constraint->getVersion());
        $operator = $constraint->getOperator();
        if (($operator === Constraint::STR_OP_GE || $operator === Constraint::STR_OP_LT) && str_ends_with($version, '-dev') && !str_starts_with($version, 'dev-')) {
            $version = substr($version, 0, -4);
        }

        return $operator . $version;
    }

    /** 6.4.24.0 => 6.4.24, 6.4.24.0-RC1 => 6.4.24-RC1, 1.0.0.0-dev => 1.0.0-dev */
    public static function shortVersion(string $normalized): string
    {
        $suffix = '';
        $dash = strpos($normalized, '-');
        if ($dash !== false) {
            $suffix = substr($normalized, $dash);
            $normalized = substr($normalized, 0, $dash);
        }
        $parts = explode('.', $normalized);
        while (count($parts) > 3 && end($parts) === '0') {
            array_pop($parts);
        }

        return implode('.', $parts) . $suffix;
    }
}
