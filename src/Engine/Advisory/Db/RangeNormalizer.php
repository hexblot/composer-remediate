<?php

declare(strict_types=1);

namespace Remediate\Engine\Advisory\Db;

use Composer\Semver\Interval;
use Composer\Semver\Intervals;
use Composer\Semver\VersionParser;

/**
 * Turns each source's version-range notation into a Composer constraint expression.
 */
final class RangeNormalizer
{
    private VersionParser $parser;

    public function __construct(?VersionParser $parser = null)
    {
        $this->parser = $parser ?? new VersionParser();
    }

    /**
     * OSV `ranges` of type ECOSYSTEM/SEMVER (events introduced/fixed/last_affected/limit) combined
     * with the explicit `versions` list: per the OSV evaluation rules a version is affected when it is
     * in either, so explicit versions outside the ranges are added as exact matches.
     *
     * @param list<array<string, mixed>> $ranges
     * @param list<string>               $versions
     */
    public function fromOsv(array $ranges, array $versions = []): ?string
    {
        $parts = [];
        foreach ($ranges as $range) {
            $type = $range['type'] ?? null;
            if (!in_array($type, ['ECOSYSTEM', 'SEMVER'], true) || !is_array($range['events'] ?? null)) {
                continue;
            }
            $introduced = null;
            foreach ($range['events'] as $event) {
                if (!is_array($event)) {
                    continue;
                }
                if (isset($event['introduced']) && is_string($event['introduced'])) {
                    $introduced = $event['introduced'];
                    continue;
                }
                $bound = null;
                if (isset($event['fixed']) && is_string($event['fixed'])) {
                    $bound = '<' . self::clean($event['fixed']);
                } elseif (isset($event['last_affected']) && is_string($event['last_affected'])) {
                    $bound = '<=' . self::clean($event['last_affected']);
                } elseif (isset($event['limit']) && is_string($event['limit']) && $event['limit'] !== '*') {
                    // "limit" caps the range without asserting a fix; versions from it onwards are not affected
                    $bound = '<' . self::clean($event['limit']);
                }
                if ($bound === null) {
                    continue;
                }
                $parts[] = ($introduced !== null && $introduced !== '0' ? '>=' . self::clean($introduced) . ',' : '') . $bound;
                $introduced = null;
            }
            if ($introduced !== null) {
                // an open-ended range: everything from "introduced" onwards
                $parts[] = $introduced === '0' ? '*' : '>=' . self::clean($introduced);
            }
        }

        $rangeExpression = implode('|', array_unique($parts));
        $rangeConstraint = null;
        if ($rangeExpression !== '') {
            try {
                $rangeConstraint = $this->parser->parseConstraints($rangeExpression);
            } catch (\UnexpectedValueException) {
                return null;
            }
        }
        foreach ($versions as $version) {
            $version = self::clean($version);
            try {
                $normalized = $this->parser->normalize($version);
            } catch (\UnexpectedValueException) {
                continue;
            }
            if ($rangeConstraint !== null && $rangeConstraint->matches(new \Composer\Semver\Constraint\Constraint('==', $normalized))) {
                continue; // already covered by a range
            }
            $parts[] = '==' . $version;
        }

        return $this->validate(implode('|', array_unique($parts)));
    }

    /**
     * FriendsOfPHP `branches`: each branch lists constraints that are ANDed; branches are ORed.
     *
     * @param array<string, mixed> $branches
     */
    public function fromFriendsOfPhp(array $branches): ?string
    {
        $parts = [];
        foreach ($branches as $branch) {
            if (!is_array($branch) || !is_array($branch['versions'] ?? null)) {
                continue;
            }
            $constraints = array_values(array_filter(array_map(static fn ($v): string => is_string($v) ? trim($v) : '', $branch['versions']), static fn (string $v): bool => $v !== ''));
            if ($constraints !== []) {
                $parts[] = implode(',', $constraints);
            }
        }

        return $this->validate(implode('|', array_unique($parts)));
    }

    /**
     * Semantic identity of an expression: the sorted numeric intervals it covers, so ">=7,<7.4.4" and
     * ">=7.0.0,<7.4.4" compare equal. Unparsable expressions fingerprint to themselves.
     */
    public function fingerprint(string $expression): string
    {
        try {
            $constraint = $this->parser->parseConstraints($expression);
        } catch (\UnexpectedValueException) {
            return 'raw:' . $expression;
        }
        $intervals = Intervals::get($constraint);
        $parts = array_map(static fn (Interval $i): string => $i->getStart()->getOperator() . $i->getStart()->getVersion() . ' ' . $i->getEnd()->getOperator() . $i->getEnd()->getVersion(), $intervals['numeric']);
        sort($parts);
        $branches = $intervals['branches'];
        $names = $branches['names'];
        sort($names);

        return implode('|', $parts) . ($names !== [] ? ' dev:' . ($branches['exclude'] ? '!' : '') . implode(',', $names) : '');
    }

    /** Returns the expression when Composer can parse it, null otherwise. */
    public function validate(string $expression): ?string
    {
        if ($expression === '') {
            return null;
        }
        try {
            $this->parser->parseConstraints($expression);

            return $expression;
        } catch (\UnexpectedValueException) {
            return null;
        }
    }

    private static function clean(string $version): string
    {
        return trim($version);
    }
}
