<?php

declare(strict_types=1);

namespace Remediate\Engine\Ranking;

use Remediate\Engine\Plan\EvaluatedCandidate;

/**
 * Deterministic priority rules, in order: no root constraint changes, no major-version changes,
 * no pre-release targets, fewest changed packages, fewest direct dependency changes, fewest
 * removals/additions, smallest version movement, then the strategy's own rank. Weights come later,
 * once fixtures justify them.
 */
final class Ranker
{
    /**
     * @param callable(string): bool $isRootRequirement
     */
    public function __construct(private $isRootRequirement)
    {
    }

    /**
     * @param list<EvaluatedCandidate> $candidates
     *
     * @return list<EvaluatedCandidate> valid candidates only, best first
     */
    public function rank(array $candidates): array
    {
        $valid = array_values(array_filter($candidates, static fn (EvaluatedCandidate $c): bool => $c->valid && $c->diff !== null));
        $keys = [];
        foreach ($valid as $index => $candidate) {
            $keys[$index] = $this->sortKey($candidate, $index);
        }
        uksort($keys, static fn (int $a, int $b): int => $keys[$a] <=> $keys[$b]);

        return array_values(array_map(static fn (int $index): EvaluatedCandidate => $valid[$index], array_keys($keys)));
    }

    /**
     * @return list<int>
     */
    public function sortKey(EvaluatedCandidate $candidate, int $index = 0): array
    {
        $diff = $candidate->diff;
        if ($diff === null) {
            return [PHP_INT_MAX];
        }
        $direct = 0;
        foreach ($diff->changedNames() as $name) {
            if (($this->isRootRequirement)($name)) {
                ++$direct;
            }
        }

        return [
            $candidate->candidate->changesRootConstraints() ? 1 : 0,
            $diff->hasMajorChange() ? 1 : 0,
            $diff->prereleaseTargets() !== [] ? 1 : 0,
            $diff->count(),
            $direct,
            count($diff->added()) + count($diff->removed()),
            $diff->versionDistance(),
            $candidate->candidate->strategy->rank(),
            $index,
        ];
    }
}
