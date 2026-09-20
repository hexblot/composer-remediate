<?php

declare(strict_types=1);

namespace Remediate\Engine\Advisory\Db;

use Composer\Semver\Comparator;
use Composer\Semver\Constraint\ConstraintInterface;
use Composer\Semver\Constraint\Constraint;
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
     * whole range rather than closing an interval of its own. Input order is therefore irrelevant and
     * "introduced 1.0, fixed 1.1, limit 2.0" affects exactly [1.0, 1.1). OSV's BeforeLimits predicate
     * accepts a version below *any* limit, so with several limits the cap is the largest one, and an
     * explicit `limit: "*"` lifts the cap altogether.
     *
     * @param list<array<string, mixed>> $ranges
     * @param list<string>               $versions
     */
    public function fromOsv(array $ranges, array $versions = []): ?string
    {
        $parts = [];
        foreach ($ranges as $range) {
            $type = $range['type'] ?? null;
            // A GIT range expresses commit boundaries, which say nothing about package versions; every
            // OSV record that has one also carries the ecosystem range that does. Skipping it loses
            // nothing. Anything else unrecognised is a different matter: a range this cannot read may
            // cover versions the ones it can read do not, so the record becomes a coverage gap rather
            // than quietly narrower coverage that reads as complete.
            if ($type === 'GIT') {
                continue;
            }
            if (!in_array($type, ['ECOSYSTEM', 'SEMVER'], true) || !is_array($range['events'] ?? null)) {
                return null;
            }
            $pieces = $this->osvRangePieces($range['events']);
            if ($pieces === null) {
                return null; // a version the ecosystem cannot express: the record becomes a coverage gap
            }
            array_push($parts, ...$pieces);
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
        $explicit = $this->explicitVersionPieces($versions, $rangeConstraint);
        if ($explicit === null) {
            return null;
        }
        array_push($parts, ...$explicit);

        return $this->validate(implode('|', array_unique($parts)));
    }

    /**
     * The constraint pieces of one OSV range: its events sorted by version and paired up, introduced
     * with the fixed or last_affected that closes it, bounded by the largest limit. Null when a version
     * cannot be normalised.
     *
     * @param array<mixed> $rawEvents
     *
     * @return list<string>|null
     */
    private function osvRangePieces(array $rawEvents): ?array
    {
        $parsed = $this->osvEvents($rawEvents);
        if ($parsed === null) {
            return null;
        }
        [$events, $limit] = $parsed;
        // Every OSV range opens with an `introduced` event. One with none, whether its event list is
        // empty or holds only closing events, states no affected interval at all; contributing nothing
        // for it narrows the record silently whenever a readable range sits beside it, so it becomes a
        // coverage gap instead. A range that does open intervals and has them all cut away by its limit
        // is a different thing: that emptiness is a reading, not a failure to read.
        if (!in_array('introduced', array_column($events, 'kind'), true)) {
            return null;
        }
        // Sort by version; at equal versions a closing event precedes the next opening one.
        usort($events, static function (array $a, array $b): int {
            if ($a['normalized'] === $b['normalized']) {
                return ($a['kind'] === 'introduced' ? 1 : 0) <=> ($b['kind'] === 'introduced' ? 1 : 0);
            }

            return Comparator::lessThan($a['normalized'], $b['normalized']) ? -1 : 1;
        });
        $pieces = [];
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
                $pieces[] = $piece;
            }
            $introduced = null;
        }
        if ($introduced !== null) {
            $piece = self::osvPiece($introduced, null, null, $limit);
            if ($piece !== null) {
                $pieces[] = $piece;
            }
        }

        return $pieces;
    }

    /**
     * Normalises the events of one OSV range. The limit is the largest one given, or none once a
     * limit is `*`. Null when a version cannot be normalised.
     *
     * @param array<mixed> $rawEvents
     *
     * @return array{list<array{kind: string, version: string, normalized: string}>, array{version: string, normalized: string}|null}|null
     */
    private function osvEvents(array $rawEvents): ?array
    {
        $events = [];
        $limit = null;
        $unlimited = false;
        foreach ($rawEvents as $event) {
            if (!is_array($event)) {
                // An event this cannot read may be the boundary that matters. Refusing the range is
                // what turns the record into a coverage gap instead of a narrower range that reads
                // as the whole truth.
                return null;
            }
            // Every key of the event has to be recognised, not just the first one that is: stopping at
            // a readable `introduced` would let the `fixed` beside it go unread, whether it holds
            // something other than a version or names a boundary this does not know. Either way the
            // range would come back looking like the whole truth with one of its edges missing. An OSV
            // event carries exactly one boundary, so an event with several is as unreadable as one with
            // none: which edge it means is a guess.
            $boundaries = [];
            foreach ($event as $kind => $value) {
                if (!in_array($kind, ['introduced', 'fixed', 'last_affected', 'limit'], true) || !is_string($value)) {
                    return null;
                }
                $boundaries[] = [$kind, $value];
            }
            if (count($boundaries) !== 1) {
                return null;
            }
            [$kind, $raw] = $boundaries[0];
            if ($kind === 'limit' && $raw === '*') {
                $unlimited = true;
                continue;
            }
            $version = $kind === 'introduced' && $raw === '0' ? '0' : self::clean($raw);
            try {
                $normalized = $version === '0' ? '0.0.0.0' : $this->parser->normalize($version);
            } catch (\UnexpectedValueException) {
                return null;
            }
            if ($kind === 'limit') {
                if ($limit === null || Comparator::greaterThan($normalized, $limit['normalized'])) {
                    $limit = ['version' => $version, 'normalized' => $normalized];
                }
                continue;
            }
            $events[] = ['kind' => $kind, 'version' => $version, 'normalized' => $normalized];
        }

        return [$events, $unlimited ? null : $limit]; // "below any limit" is always true once one limit is infinite
    }

    /**
     * Exact-version pieces for the OSV `versions` list, leaving out versions the ranges already cover
     * and versions that do not normalise.
     *
     * @param list<string> $versions
     *
     * @return list<string>|null null when a listed version cannot be placed at all
     */
    private function explicitVersionPieces(array $versions, ?ConstraintInterface $covered): ?array
    {
        $pieces = [];
        foreach ($versions as $version) {
            $version = self::clean($version);
            try {
                $normalized = $this->parser->normalize($version);
            } catch (\UnexpectedValueException) {
                // A version named as affected that cannot be understood is not a version to leave out;
                // it is one this cannot rule in or out, which is what a coverage gap is for.
                return null;
            }
            if ($covered !== null && $covered->matches(new Constraint('==', $normalized))) {
                continue;
            }
            $pieces[] = '==' . $version;
        }

        return $pieces;
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
            // A branch this cannot read covers versions the readable branches may not. Skipping it
            // would hand back the readable branches as though they were the whole advisory, which is
            // the same silent narrowing the OSV path refuses.
            if (!is_array($branch) || !is_array($branch['versions'] ?? null)) {
                return null;
            }
            $versions = array_values($branch['versions']);
            $constraints = array_values(array_filter(array_map(static fn ($v): string => is_string($v) ? trim($v) : '', $versions), static fn (string $v): bool => $v !== ''));
            if (count($constraints) !== count($versions)) {
                return null;
            }
            // A branch listing no versions constrains nothing, so it covers everything or nothing and
            // there is no telling which. Dropping it leaves the readable branches reading as the whole
            // advisory; the reader already treats it as a gap when it stands alone, and a readable
            // branch beside it must not erase that.
            if ($constraints === []) {
                return null;
            }
            $parts[] = implode(',', $constraints);
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
