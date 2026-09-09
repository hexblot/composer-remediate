<?php

declare(strict_types=1);

namespace Remediate\Engine\Advisory\Db;

use Composer\Semver\Comparator;
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
     * OSV `ranges` of type ECOSYSTEM/SEMVER combined with the explicit `versions` list: per the OSV
     * evaluation rules a version is affected when it is in either, so explicit versions outside the
     * ranges are added as exact matches.
     *
     * Events are evaluated the way the OSV specification describes: sorted by version, `introduced`
     * opens an affected interval, the next `fixed` or `last_affected` closes it, and `limit` caps the
     * whole range (every interval is cut at the smallest limit) rather than closing an interval of its
     * own. Input order is therefore irrelevant and "introduced 1.0, fixed 1.1, limit 2.0" affects
     * exactly [1.0, 1.1).
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
            /** @var list<array{kind: string, version: string, normalized: string}> $events */
            $events = [];
            $limit = null;
            foreach ($range['events'] as $event) {
                if (!is_array($event)) {
                    continue;
                }
                foreach (['introduced', 'fixed', 'last_affected', 'limit'] as $kind) {
                    if (!isset($event[$kind]) || !is_string($event[$kind])) {
                        continue;
                    }
                    $raw = $event[$kind];
                    if ($kind === 'limit' && $raw === '*') {
                        break;
                    }
                    $version = $kind === 'introduced' && $raw === '0' ? '0' : self::clean($raw);
                    try {
                        $normalized = $version === '0' ? '0.0.0.0' : $this->parser->normalize($version);
                    } catch (\UnexpectedValueException) {
                        return null; // a version the ecosystem cannot express: the record becomes a coverage gap
                    }
                    if ($kind === 'limit') {
                        if ($limit === null || Comparator::lessThan($normalized, $limit['normalized'])) {
                            $limit = ['version' => $version, 'normalized' => $normalized];
                        }
                        break;
                    }
                    $events[] = ['kind' => $kind, 'version' => $version, 'normalized' => $normalized];
                    break;
                }
            }
            // Sort by version; at equal versions a closing event precedes the next opening one.
            usort($events, static function (array $a, array $b): int {
                if ($a['normalized'] === $b['normalized']) {
                    return ($a['kind'] === 'introduced' ? 1 : 0) <=> ($b['kind'] === 'introduced' ? 1 : 0);
                }

                return Comparator::lessThan($a['normalized'], $b['normalized']) ? -1 : 1;
            });
            $introduced = null;
            foreach ($events as $event) {
                if ($event['kind'] === 'introduced') {
                    $introduced ??= $event;
                    continue;
                }
                if ($introduced === null) {
                    continue; // a fix without an introduction closes nothing
                }
                $piece = self::osvPiece($introduced, $event['kind'] === 'fixed' ? '<' : '<=', $event, $limit);
                if ($piece !== null) {
                    $parts[] = $piece;
                }
                $introduced = null;
            }
            if ($introduced !== null) {
                $piece = self::osvPiece($introduced, null, null, $limit);
                if ($piece !== null) {
                    $parts[] = $piece;
                }
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
     * One affected interval as a Composer constraint, cut at the range's limit when there is one.
     *
     * @param array{kind: string, version: string, normalized: string}      $introduced
     * @param array{kind: string, version: string, normalized: string}|null $end
     * @param array{version: string, normalized: string}|null               $limit
     */
    private static function osvPiece(array $introduced, ?string $endOperator, ?array $end, ?array $limit): ?string
    {
        $lower = $introduced['version'] === '0' ? null : '>=' . $introduced['version'];
        $upper = $end !== null && $endOperator !== null ? $endOperator . $end['version'] : null;
        if ($limit !== null) {
            if ($lower !== null && !Comparator::lessThan($introduced['normalized'], $limit['normalized'])) {
                return null; // the interval starts at or beyond the limit: nothing of it is affected
            }
            if ($upper === null || Comparator::lessThan($limit['normalized'], $end['normalized'] ?? $limit['normalized']) || ($endOperator === '<=' && $limit['normalized'] === ($end['normalized'] ?? ''))) {
                $upper = '<' . $limit['version'];
            }
        }
        if ($lower === null && $upper === null) {
            return '*';
        }

        return implode(',', array_filter([$lower, $upper], static fn (?string $p): bool => $p !== null));
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
