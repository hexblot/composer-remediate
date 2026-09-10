<?php

declare(strict_types=1);

namespace Remediate\Engine\Plan;

use Composer\DependencyResolver\Request;
use Remediate\Engine\Candidate\Candidate;
use Remediate\Engine\Candidate\Strategy;
use Remediate\Engine\Matching\Finding;

/**
 * State of the global search for one command that fixes every finding: which plans contribute, which
 * of their ranked candidates is currently chosen, the best combination so far and every attempt made.
 * The planner drives the search (it owns the solver and the acceptance rules); this class owns the
 * bookkeeping and the heuristics that pick what to try next.
 */
final class CombinedSearch
{
    /** @var list<CombinedAttempt> */
    public array $attempts = [];

    public ?CombinedRemediation $best = null;

    /** @var array<int, int> contributing plan => index into its ranked candidates, for the best combination */
    public array $bestChoice;

    /** The solver's explanation for the last combination that did not resolve, for targeting the next swap. */
    public string $lastReason = '';

    /** @var array<string, true> */
    private array $seen = [];

    /**
     * @param array<int, list<EvaluatedCandidate>> $ranked  valid candidates per contributing plan, best first
     * @param list<FindingPlan>                    $plans   every plan, indexed as $ranked is
     * @param array<string, true>                  $allKeys every finding key the combination must fix
     */
    private function __construct(
        public readonly array $ranked,
        public readonly array $plans,
        public readonly array $allKeys,
    ) {
        $this->bestChoice = array_map(static fn (): int => 0, $ranked);
    }

    /**
     * @param list<FindingPlan> $plans
     *
     * @return self|null null when no plan has a valid candidate
     */
    public static function over(array $plans): ?self
    {
        $allKeys = [];
        $ranked = [];
        foreach ($plans as $index => $plan) {
            foreach ($plan->allFindings() as $finding) {
                $allKeys[$finding->key()] = true;
            }
            if ($plan->ranked !== []) {
                $ranked[$index] = $plan->ranked;
            }
        }

        return $ranked === [] ? null : new self($ranked, $plans, $allKeys);
    }

    public function contributorCount(): int
    {
        return count($this->ranked);
    }

    /** The single contributing plan's winner, for the case where nothing needs merging. */
    public function soleWinner(): EvaluatedCandidate
    {
        foreach ($this->ranked as $candidates) {
            return $candidates[0];
        }

        throw new \LogicException('no contributing plan');
    }

    /**
     * The command for a choice of candidates, or null when that exact command was already tried.
     *
     * @param array<int, int> $choice
     */
    public function merged(array $choice): ?Candidate
    {
        $merged = self::mergeCandidates(array_map(fn (int $plan, int $rank): Candidate => $this->ranked[$plan][$rank]->candidate, array_keys($choice), array_values($choice)));
        if (isset($this->seen[$merged->signature()])) {
            return null;
        }
        $this->seen[$merged->signature()] = true;

        return $merged;
    }

    public function record(CombinedAttempt $attempt): void
    {
        $this->attempts[] = $attempt;
        if ($attempt->outcome === CombinedOutcome::Unresolved) {
            $this->lastReason = (string) $attempt->reason;
        }
    }

    /**
     * Adopts the result as the best so far when it fixes more findings, or as many with a smaller diff.
     *
     * @param array<int, int> $choice
     */
    public function adoptIfBetter(?CombinedRemediation $result, array $choice): bool
    {
        if ($result === null) {
            return false;
        }
        $best = $this->best;
        if ($best === null || $result->fixedCount() > $best->fixedCount() || ($result->fixedCount() === $best->fixedCount() && $result->diff->count() < $best->diff->count())) {
            $this->best = $result;
            $this->bestChoice = $choice;

            return true;
        }

        return false;
    }

    public function fixesAll(): bool
    {
        return $this->best !== null && $this->best->fixesAll();
    }

    /** Marks every attempt whose command is the chosen one. */
    public function markChosen(): void
    {
        if ($this->best === null) {
            return;
        }
        foreach ($this->attempts as $i => $attempt) {
            if ($attempt->candidate->signature() === $this->best->candidate->signature()) {
                $this->attempts[$i] = $attempt->withChosen(true);
            }
        }
    }

    /**
     * The contributing plans whose candidate should be swapped next: those whose findings the best
     * combination left unfixed, or, when the solver found no solution, those whose command names a
     * package the solver complained about; every contributor when nothing narrower can be told.
     *
     * @return list<int>
     */
    public function plansInTheWay(): array
    {
        $targets = [];
        if ($this->best !== null) {
            $unfixed = array_flip($this->best->unfixedKeys);
            foreach (array_keys($this->bestChoice) as $index) {
                foreach ($this->plans[$index]->allFindings() as $finding) {
                    if (isset($unfixed[$finding->key()])) {
                        $targets[] = $index;
                        break;
                    }
                }
            }
        } elseif ($this->lastReason !== '') {
            foreach ($this->bestChoice as $index => $rank) {
                $candidate = $this->ranked[$index][$rank]->candidate;
                foreach ([...$candidate->allowList, ...array_keys($candidate->pins), ...array_keys($candidate->temporaryConstraints)] as $name) {
                    if (str_contains($this->lastReason, (string) $name)) {
                        $targets[] = $index;
                        break;
                    }
                }
            }
        }
        if ($targets === []) {
            $targets = array_keys($this->bestChoice);
        }

        return array_values(array_unique($targets));
    }

    /**
     * The active contributors the shrink step should try dropping: those whose vulnerable packages a
     * sibling's own solve already moves. Dropping any other one would leave its finding in place.
     *
     * @param array<int, int> $active
     *
     * @return list<int>
     */
    public function droppable(array $active): array
    {
        $movedBySiblings = [];
        foreach ($active as $index => $rank) {
            $diff = $this->ranked[$index][$rank]->diff;
            $movedBySiblings[$index] = $diff === null ? [] : array_flip($diff->changedNames());
        }
        $covered = [];
        foreach (array_keys($active) as $index) {
            $names = array_flip(array_map(static fn (Finding $f): string => $f->packageName, $this->plans[$index]->allFindings()));
            foreach ($movedBySiblings as $sibling => $moved) {
                if ($sibling !== $index && array_intersect_key($names, $moved) !== []) {
                    $covered[] = $index;
                    break;
                }
            }
        }

        return $covered;
    }

    public function packageOf(int $index): string
    {
        return $this->plans[$index]->finding->packageName;
    }

    /**
     * One command carrying several candidates: the union of their allow lists, pins, temporary
     * constraints and root changes, the widest transitive mode, -m when any of them used it. Components
     * are sorted so the text does not depend on report order.
     *
     * @param list<Candidate> $candidates
     */
    public static function mergeCandidates(array $candidates): Candidate
    {
        $allow = [];
        $pins = [];
        $temporary = [];
        $roots = [];
        $extra = [];
        $mode = Request::UPDATE_ONLY_LISTED;
        $minimal = false;
        $strategy = Strategy::LockRefresh;
        foreach ($candidates as $c) {
            foreach ($c->allowList as $name) {
                $allow[$name] = true;
            }
            $pins += $c->pins;
            $temporary += $c->temporaryConstraints;
            $roots += $c->rootConstraintChanges;
            array_push($extra, ...$c->extraArguments);
            $mode = max($mode, $c->transitiveMode);
            $minimal = $minimal || $c->minimalChanges;
            if ($c->strategy->rank() > $strategy->rank()) {
                $strategy = $c->strategy;
            }
        }
        ksort($allow);
        ksort($pins);
        ksort($temporary);
        ksort($roots);

        return new Candidate($strategy, array_keys($allow), $mode, $temporary, $minimal, $roots, 'all per-package remediations in one command', $pins, array_values(array_unique($extra)));
    }
}
