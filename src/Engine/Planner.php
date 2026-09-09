<?php

declare(strict_types=1);

namespace Remediate\Engine;

use Composer\Semver\Comparator;
use Composer\Semver\Constraint\MultiConstraint;
use Remediate\Engine\Advisory\AdvisoryProvider;
use Remediate\Engine\Candidate\Candidate;
use Remediate\Engine\Candidate\CandidateGenerator;
use Remediate\Engine\Candidate\FixedRangeResolver;
use Remediate\Engine\Candidate\Strategy;
use Remediate\Engine\Graph\DependencyGraph;
use Remediate\Engine\Matching\Finding;
use Remediate\Engine\Matching\Matcher;
use Remediate\Engine\Plan\EvaluatedCandidate;
use Remediate\Engine\Plan\FindingPlan;
use Remediate\Engine\Plan\Plan;
use Remediate\Engine\Lock\LockSnapshot;
use Remediate\Engine\Project\ProjectContext;
use Remediate\Engine\Ranking\Ranker;
use Remediate\Engine\Solver\LockDiff;
use Remediate\Engine\Solver\ScratchWorkspace;
use Remediate\Engine\Solver\SolveStatus;
use Remediate\Engine\Solver\SolverInterface;

final class Planner
{
    /** Maximum number of downward probes when searching for the lowest working parent version. */
    public const MAX_DESCENT_STEPS = 6;

    /** @var callable(string): void|null */
    private $progress;

    public function __construct(
        private readonly AdvisoryProvider $advisories,
        private readonly SolverInterface $solver,
        private readonly CandidateGenerator $generator = new CandidateGenerator(),
        private readonly bool $includeDev = true,
        private readonly int $maxCandidatesPerFinding = 10,
        ?callable $progress = null,
    ) {
        $this->progress = $progress;
    }

    public function plan(ProjectContext $context, ScratchWorkspace $workspace): Plan
    {
        $lock = $context->lockSnapshot();
        $graph = new DependencyGraph($context->rootPackage(), $context->lockedRepository());
        $matcher = new Matcher($this->advisories);
        $isRoot = static fn (string $name): bool => $context->isRootRequirement($name);
        $ranker = new Ranker($isRoot);
        $warnings = [];

        if (!$this->advisories->isComplete()) {
            $warnings[] = sprintf('Advisory source "%s" only knows advisories for the current lock; candidate locks cannot be checked for other advisories.', $this->advisories->describe());
        }

        $findings = $matcher->match($lock, $isRoot);
        if (!$this->includeDev) {
            $findings = array_values(array_filter($findings, static fn (Finding $f): bool => !$f->isDev));
        }
        $baseline = [];
        foreach ($findings as $finding) {
            $baseline[$finding->key()] = true;
        }

        // Several advisories on one package are remediated together: one command must escape all of them.
        $groups = [];
        foreach ($findings as $finding) {
            $groups[$finding->packageName][] = $finding;
        }

        $plans = [];
        foreach ($groups as $group) {
            $finding = $group[0]->withPaths($graph->pathsToRoot($group[0]->packageName));
            $related = array_slice($group, 1);
            $groupKeys = [];
            $affected = [];
            foreach ($group as $member) {
                $groupKeys[$member->key()] = true;
                $affected[] = $member->advisory->affectedVersions;
            }
            $combinedAffected = count($affected) === 1 ? $affected[0] : MultiConstraint::create($affected, false);
            $this->report(sprintf('%s on %s %s', implode(', ', array_map(static fn (Finding $f): string => $f->advisory->displayId(), $group)), $finding->packageName, $finding->prettyVersion));

            $candidates = $this->generator->generate($finding, $graph, $context->rootRequirements(), $combinedAffected);
            if ($candidates === []) {
                $plans[] = new FindingPlan($finding, [], [], sprintf('No release of %s newer than %s is outside the affected range %s.', $finding->packageName, $finding->prettyVersion, $combinedAffected->getPrettyString()), [], $related);
                continue;
            }

            $evaluated = [];
            $skipped = [];
            $transportFailures = 0;
            foreach (array_slice($candidates, 0, $this->maxCandidatesPerFinding) as $candidate) {
                // Ranking rule 1: any candidate without root constraint changes beats every candidate with them.
                if ($candidate->changesRootConstraints() && self::hasValidWithoutRootChanges($evaluated)) {
                    $skipped[] = $candidate;
                    continue;
                }
                $evaluation = $this->evaluate($candidate, $finding, $groupKeys, $lock, $baseline, $matcher, $workspace);
                if ($evaluation->result->status === SolveStatus::Transport) {
                    ++$transportFailures;
                }
                $evaluated[] = $evaluation;
                if ($evaluation->valid && !self::descentIsDominated($evaluation, $evaluated, $ranker)) {
                    array_push($evaluated, ...$this->descendParent($evaluation, $finding, $groupKeys, $lock, $baseline, $matcher, $workspace));
                }
            }

            $blocker = null;
            if ($transportFailures > 0 && $transportFailures === count($evaluated)) {
                $blocker = 'Every solve failed with a network error; package metadata could not be fetched.';
            }
            $plans[] = new FindingPlan($finding, $evaluated, $ranker->rank($evaluated), $blocker, $skipped, $related);
        }

        return new Plan($plans, [
            'project' => $context->directory,
            'composer_version' => $context->composerVersion(),
            'php_version' => PHP_VERSION,
            'advisory_source' => $this->advisories->describe(),
            'solver' => $this->solver->describe(),
            'composer_json_sha256' => self::fileHash($context->composerJsonPath()),
            'composer_lock_sha256' => self::fileHash($context->lockPath()),
            'analysis_timestamp' => gmdate('c'),
            'locked_packages' => (string) $lock->count(),
        ], $warnings);
    }

    /**
     * @param list<EvaluatedCandidate> $evaluated
     */
    private static function hasValidWithoutRootChanges(array $evaluated): bool
    {
        foreach ($evaluated as $candidate) {
            if ($candidate->valid && !$candidate->candidate->changesRootConstraints()) {
                return true;
            }
        }

        return false;
    }

    /**
     * A descent can at best reach two changed packages (the parent and the vulnerable package) with no
     * major change. Skip it when an already valid candidate is at least that good.
     *
     * @param list<EvaluatedCandidate> $evaluated
     */
    private static function descentIsDominated(EvaluatedCandidate $start, array $evaluated, Ranker $ranker): bool
    {
        $optimistic = [$start->candidate->changesRootConstraints() ? 1 : 0, 0, 2, 0, 0, 0, 0, 0];
        foreach ($evaluated as $candidate) {
            if ($candidate === $start || !$candidate->valid) {
                continue;
            }
            if ($ranker->sortKey($candidate) <= $optimistic) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param array<string, true> $groupKeys finding keys this candidate must remove
     * @param array<string, true> $baseline  finding keys present before remediation
     */
    private function evaluate(Candidate $candidate, Finding $finding, array $groupKeys, LockSnapshot $lock, array $baseline, Matcher $matcher, ScratchWorkspace $workspace): EvaluatedCandidate
    {
        $this->report('  trying ' . $candidate->commandLine($this->solver->supportsMinimalChanges()));
        $result = $this->solver->solve($candidate, $workspace);

        if (!$result->resolved() || $result->after === null) {
            return new EvaluatedCandidate($candidate, $result, null, false, self::describeFailure($result->status) . ': ' . $result->explanation());
        }

        $diff = LockDiff::between($lock, $result->after);
        $afterKeys = $matcher->findingKeys($result->after);
        $remaining = array_keys(array_intersect_key($afterKeys, $groupKeys));
        if ($remaining !== []) {
            $after = $result->after->get($finding->packageName);

            return new EvaluatedCandidate($candidate, $result, $diff, false, sprintf('resolves, but %s ends at %s which is still affected by %s', $finding->packageName, $after?->getPrettyVersion() ?? '?', implode(', ', array_map(static fn (string $k): string => explode('@', $k)[0], $remaining))));
        }
        $introduced = array_keys(array_diff_key($afterKeys, $baseline));
        if ($introduced !== []) {
            return new EvaluatedCandidate($candidate, $result, $diff, false, 'resolves, but introduces new advisories: ' . implode(', ', $introduced));
        }
        if ($diff->count() === 0) {
            return new EvaluatedCandidate($candidate, $result, $diff, false, 'resolves without changing anything');
        }

        return new EvaluatedCandidate($candidate, $result, $diff, true, null);
    }

    /**
     * `composer update A -W -m` moves A to its newest allowed version. A human asking for the
     * smallest change wants the *lowest* version of A that still admits the fix. Probe downwards
     * with a temporary upper bound until the solve breaks, then pin the lowest working version.
     *
     * @param array<string, true> $groupKeys
     * @param array<string, true> $baseline
     *
     * @return list<EvaluatedCandidate>
     */
    private function descendParent(EvaluatedCandidate $start, Finding $finding, array $groupKeys, LockSnapshot $lock, array $baseline, Matcher $matcher, ScratchWorkspace $workspace): array
    {
        $candidate = $start->candidate;
        if (!in_array($candidate->strategy, [Strategy::ParentUpdate, Strategy::RootConstraintWiden], true) || count($candidate->allowList) !== 1 || $candidate->pins !== [] || $start->result->after === null) {
            return [];
        }
        $parent = $candidate->allowList[0];
        if ($parent === $finding->packageName) {
            return [];
        }
        $before = $lock->get($parent);
        $after = $start->result->after->get($parent);
        if ($before === null || $after === null || str_starts_with($before->getVersion(), 'dev-') || str_starts_with($after->getVersion(), 'dev-')) {
            return [];
        }

        $high = $after->getVersion();
        $lowerBound = '>' . FixedRangeResolver::shortVersion($before->getVersion());
        $best = null;
        for ($step = 0; $step < self::MAX_DESCENT_STEPS; ++$step) {
            $probe = $candidate->withTemporaryConstraints(
                [$parent => $lowerBound . ',<' . FixedRangeResolver::shortVersion($high)],
                sprintf('probe: is there a lower %s than %s that still admits the fix?', $parent, $after->getPrettyVersion()),
            );
            $evaluation = $this->evaluate($probe, $finding, $groupKeys, $lock, $baseline, $matcher, $workspace);
            $probed = $evaluation->result->after?->get($parent);
            if (!$evaluation->valid || $probed === null || !Comparator::lessThan($probed->getVersion(), $high)) {
                break;
            }
            $high = $probed->getVersion();
            $best = $probed->getPrettyVersion();
        }

        if ($best === null) {
            return [];
        }
        $pinned = $candidate->withPin($parent, $best, sprintf('%s, pinned to %s, the lowest version that admits the fix', $candidate->description, $best));
        $final = $this->evaluate($pinned, $finding, $groupKeys, $lock, $baseline, $matcher, $workspace);

        return $final->valid ? [$final] : [];
    }

    private static function fileHash(string $path): string
    {
        if (!is_file($path)) {
            return '';
        }
        $hash = hash_file('sha256', $path);

        return $hash === false ? '' : $hash;
    }

    private static function describeFailure(SolveStatus $status): string
    {
        return match ($status) {
            SolveStatus::Conflict => 'Composer could not resolve the dependencies',
            SolveStatus::Transport => 'network error while fetching package metadata',
            SolveStatus::Error => 'Composer failed',
            SolveStatus::Resolved => 'unexpected',
        };
    }

    private function report(string $message): void
    {
        if ($this->progress !== null) {
            ($this->progress)($message);
        }
    }
}
