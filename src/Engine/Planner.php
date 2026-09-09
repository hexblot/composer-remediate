<?php

declare(strict_types=1);

namespace Remediate\Engine;

use Composer\DependencyResolver\Request;
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
use Remediate\Engine\Plan\CombinedRemediation;
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

    /** Maximum number of times a conflicting candidate is widened with the locked packages Composer names as blockers. */
    public const MAX_EXPANSIONS = 8;

    /** @var callable(string): void|null */
    private $progress;

    /**
     * @param list<string> $ignoredAdvisories advisory ids or CVEs to leave out entirely
     */
    public function __construct(
        private readonly AdvisoryProvider $advisories,
        private readonly SolverInterface $solver,
        private readonly CandidateGenerator $generator = new CandidateGenerator(),
        private readonly bool $includeDev = true,
        private readonly int $maxCandidatesPerFinding = 10,
        ?callable $progress = null,
        private readonly array $ignoredAdvisories = [],
    ) {
        $this->progress = $progress;
    }

    public static function engineVersion(): string
    {
        if (class_exists(\Composer\InstalledVersions::class) && \Composer\InstalledVersions::isInstalled('hexblot/composer-remediate')) {
            return \Composer\InstalledVersions::getPrettyVersion('hexblot/composer-remediate') ?? 'dev';
        }

        return 'dev';
    }

    public function plan(ProjectContext $context, ScratchWorkspace $workspace): Plan
    {
        $lock = $context->lockSnapshot();
        $graph = new DependencyGraph($context->rootPackage(), $context->lockedRepository());
        $matcher = (new Matcher($this->advisories))->withIgnored($this->ignoredAdvisories);
        $isRoot = static fn (string $name): bool => $context->isRootRequirement($name);
        $ranker = new Ranker($isRoot);
        $warnings = [];

        if (!$this->advisories->isComplete()) {
            $warnings[] = sprintf('Advisory source "%s" only knows advisories for the current lock; candidate locks cannot be checked for other advisories.', $this->advisories->describe());
        }

        $findings = $matcher->match($lock, $isRoot);
        if ($matcher->ignoredCount() > 0) {
            $warnings[] = sprintf('%d advisory match%s ignored per configuration (--ignore, config.audit.ignore or config.policy).', $matcher->ignoredCount(), $matcher->ignoredCount() === 1 ? '' : 'es');
        }
        if (!$this->includeDev) {
            $findings = array_values(array_filter($findings, static fn (Finding $f): bool => !$f->isDev));
        }
        // Production findings first, development-only findings after them.
        usort($findings, static fn (Finding $a, Finding $b): int => [$a->isDev ? 1 : 0, $a->packageName, $a->advisory->id] <=> [$b->isDev ? 1 : 0, $b->packageName, $b->advisory->id]);
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
            $seen = [];
            foreach (array_slice($candidates, 0, $this->maxCandidatesPerFinding) as $candidate) {
                // Ranking rule 1: any candidate without root constraint changes beats every candidate with them.
                if ($candidate->changesRootConstraints() && self::hasValidWithoutRootChanges($evaluated)) {
                    $skipped[] = $candidate;
                    continue;
                }
                // Conflict expansion can produce the same allow-list set another path already reached.
                if (isset($seen[$candidate->signature()])) {
                    continue;
                }
                $seen[$candidate->signature()] = true;
                $evaluation = $this->evaluate($candidate, $finding, $groupKeys, $lock, $baseline, $matcher, $workspace);
                if ($evaluation->result->status === SolveStatus::Transport) {
                    ++$transportFailures;
                }
                $evaluated[] = $evaluation;
                if ($evaluation->result->status === SolveStatus::Conflict) {
                    $expanded = $this->expandOnConflict($evaluation, $finding, $groupKeys, $lock, $baseline, $matcher, $workspace, $seen);
                    array_push($evaluated, ...$expanded);
                    $evaluation = $expanded === [] ? $evaluation : $expanded[count($expanded) - 1];
                }
                if ($evaluation->valid && !self::descentIsDominated($evaluation, $evaluated, $ranker)) {
                    array_push($evaluated, ...$this->descendParent($evaluation, $finding, $groupKeys, $lock, $baseline, $matcher, $workspace));
                }
            }

            $blocker = null;
            if ($transportFailures > 0 && $transportFailures === count($evaluated)) {
                $blocker = 'Every solve failed with a network error; package metadata could not be fetched.';
            }
            $ranked = $ranker->rank($evaluated);
            if ($ranked !== []) {
                $ranked[0] = $this->simplify($ranked[0], $finding, $groupKeys, $lock, $baseline, $matcher, $workspace);
            }
            $plans[] = new FindingPlan($finding, $evaluated, $ranked, $blocker, $skipped, $related);
        }

        $combined = $this->combine($plans, $lock, $baseline, $matcher, $workspace);

        return new Plan($plans, [
            'project' => $context->directory,
            'engine_version' => self::engineVersion(),
            'composer_version' => $context->composerVersion(),
            'php_version' => PHP_VERSION,
            'advisory_source' => $this->advisories->describe(),
            'solver' => $this->solver->describe(),
            'composer_json_sha256' => self::fileHash($context->composerJsonPath()),
            'composer_lock_sha256' => self::fileHash($context->lockPath()),
            'analysis_timestamp' => gmdate('c'),
            'locked_packages' => (string) $lock->count(),
        ], $warnings, $combined);
    }

    /**
     * Merge the per-package winners into one command and verify it with a single solve. The result
     * may fix everything, only some findings (reported as k of n), or not resolve at all.
     *
     * @param list<FindingPlan>   $plans
     * @param array<string, true> $baseline
     */
    private function combine(array $plans, LockSnapshot $lock, array $baseline, Matcher $matcher, ScratchWorkspace $workspace): ?CombinedRemediation
    {
        $winners = [];
        $allKeys = [];
        foreach ($plans as $plan) {
            foreach ($plan->allFindings() as $finding) {
                $allKeys[$finding->key()] = true;
            }
            $recommended = $plan->recommended();
            if ($recommended !== null) {
                $winners[] = $recommended;
            }
        }
        if ($winners === []) {
            return null;
        }

        if (count($winners) === 1 && $winners[0]->result->after !== null && $winners[0]->diff !== null) {
            $afterKeys = $matcher->findingKeys($winners[0]->result->after);

            return new CombinedRemediation($winners[0]->candidate, $winners[0]->result, $winners[0]->diff, array_keys(array_diff_key($allKeys, $afterKeys)), array_keys(array_intersect_key($allKeys, $afterKeys)));
        }

        $allow = [];
        $pins = [];
        $temporary = [];
        $roots = [];
        $mode = Request::UPDATE_ONLY_LISTED;
        $minimal = false;
        $strategy = Strategy::LockRefresh;
        foreach ($winners as $winner) {
            $c = $winner->candidate;
            foreach ($c->allowList as $name) {
                $allow[$name] = true;
            }
            $pins += $c->pins;
            $temporary += $c->temporaryConstraints;
            $roots += $c->rootConstraintChanges;
            $mode = max($mode, $c->transitiveMode);
            $minimal = $minimal || $c->minimalChanges;
            if ($c->strategy->rank() > $strategy->rank()) {
                $strategy = $c->strategy;
            }
        }
        $merged = new Candidate($strategy, array_keys($allow), $mode, $temporary, $minimal, $roots, 'all per-package remediations in one command', $pins);

        $this->report('combining: ' . $merged->commandLine($this->solver->supportsMinimalChanges()));
        $result = $this->solver->solve($merged, $workspace);
        if (!$result->resolved() || $result->after === null) {
            return null;
        }
        $afterKeys = $matcher->findingKeys($result->after);
        if (array_diff_key($afterKeys, $baseline) !== []) {
            return null; // introduces advisories that were not there before
        }
        $fixed = array_keys(array_diff_key($allKeys, $afterKeys));
        $unfixed = array_keys(array_intersect_key($allKeys, $afterKeys));
        $combined = new CombinedRemediation($merged, $result, LockDiff::between($lock, $result->after), $fixed, $unfixed);

        // Prefer the simplest spelling that yields the identical lock.
        foreach (self::simplerVariants($merged) as $variant) {
            $variantResult = $this->solver->solve($variant, $workspace);
            if ($variantResult->resolved() && $variantResult->after !== null && self::sameVersions($variantResult->after, $result->after)) {
                return new CombinedRemediation($variant, $variantResult, $combined->diff, $fixed, $unfixed);
            }
        }

        return $combined;
    }

    /** @return list<Candidate> */
    private static function simplerVariants(Candidate $c): array
    {
        $variants = [];
        if ($c->temporaryConstraints !== [] && $c->minimalChanges) {
            $variants[] = new Candidate($c->strategy, $c->allowList, $c->transitiveMode, [], false, $c->rootConstraintChanges, $c->description, $c->pins);
        }
        if ($c->temporaryConstraints !== []) {
            $variants[] = new Candidate($c->strategy, $c->allowList, $c->transitiveMode, [], $c->minimalChanges, $c->rootConstraintChanges, $c->description, $c->pins);
        }
        if ($c->minimalChanges) {
            $variants[] = new Candidate($c->strategy, $c->allowList, $c->transitiveMode, $c->temporaryConstraints, false, $c->rootConstraintChanges, $c->description, $c->pins);
        }

        return $variants;
    }

    /**
     * The temporary constraint and -m exist to steer the solver; a human types neither when the plain
     * command already produces the same lock. Try the simpler spellings and keep the simplest one
     * that yields exactly the same package versions.
     *
     * @param array<string, true> $groupKeys
     * @param array<string, true> $baseline
     */
    private function simplify(EvaluatedCandidate $winner, Finding $finding, array $groupKeys, LockSnapshot $lock, array $baseline, Matcher $matcher, ScratchWorkspace $workspace): EvaluatedCandidate
    {
        $c = $winner->candidate;
        if ($winner->result->after === null || ($c->temporaryConstraints === [] && !$c->minimalChanges)) {
            return $winner;
        }
        $variants = [];
        if ($c->temporaryConstraints !== [] && $c->minimalChanges) {
            $variants[] = new Candidate($c->strategy, $c->allowList, $c->transitiveMode, [], false, $c->rootConstraintChanges, $c->description, $c->pins);
        }
        if ($c->temporaryConstraints !== []) {
            $variants[] = new Candidate($c->strategy, $c->allowList, $c->transitiveMode, [], $c->minimalChanges, $c->rootConstraintChanges, $c->description, $c->pins);
        }
        if ($c->minimalChanges) {
            $variants[] = new Candidate($c->strategy, $c->allowList, $c->transitiveMode, $c->temporaryConstraints, false, $c->rootConstraintChanges, $c->description, $c->pins);
        }
        foreach ($variants as $variant) {
            $evaluation = $this->evaluate($variant, $finding, $groupKeys, $lock, $baseline, $matcher, $workspace);
            if ($evaluation->valid && $evaluation->result->after !== null && self::sameVersions($evaluation->result->after, $winner->result->after)) {
                return $evaluation;
            }
        }

        return $winner;
    }

    private static function sameVersions(LockSnapshot $a, LockSnapshot $b): bool
    {
        if ($a->names() !== $b->names()) {
            return false;
        }
        foreach ($a->packages as $name => $package) {
            $other = $b->get($name);
            if ($other === null || $other->getVersion() !== $package->getVersion()) {
                return false;
            }
        }

        return true;
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
        $optimistic = [$start->candidate->changesRootConstraints() ? 1 : 0, 0, 0, 2, 0, 0, 0, 0, 0];
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
     * When Composer reports "X is locked to version … and an update of this package was not requested",
     * X is a sibling that pins something the candidate needs to move (shopware/administration pinning
     * shopware/core, drupal/core-dev pinning drupal/core). Add the named packages to the allow list and
     * retry, a bounded number of times. Only parent-level strategies are widened; the vulnerable
     * package itself is never added as a way around a failing single-package update.
     *
     * @param array<string, true> $groupKeys
     * @param array<string, true> $baseline
     *
     * @param array<string, true> $seen      solver requests already evaluated for this finding (updated in place)
     *
     * @return list<EvaluatedCandidate> every retried candidate, in order
     */
    private function expandOnConflict(EvaluatedCandidate $failed, Finding $finding, array $groupKeys, LockSnapshot $lock, array $baseline, Matcher $matcher, ScratchWorkspace $workspace, array &$seen): array
    {
        $candidate = $failed->candidate;
        if (!in_array($candidate->strategy, [Strategy::ParentUpdate, Strategy::RootConstraintWiden], true) || $candidate->transitiveMode !== Request::UPDATE_LISTED_WITH_TRANSITIVE_DEPS) {
            return [];
        }
        $results = [];
        $current = $failed;
        for ($step = 0; $step < self::MAX_EXPANSIONS; ++$step) {
            $blockers = self::lockedBlockers($current->result->output, $current->candidate->allowList, $finding->packageName);
            if ($blockers === []) {
                break;
            }
            $allowList = array_values(array_unique([...$current->candidate->allowList, ...$blockers]));
            $widened = $current->candidate->withAllowList($allowList, sprintf('%s; also updating %s, which Composer reported as locked blockers', $current->candidate->description, implode(', ', $blockers)));
            if (isset($seen[$widened->signature()])) {
                break;
            }
            $seen[$widened->signature()] = true;
            $current = $this->evaluate($widened, $finding, $groupKeys, $lock, $baseline, $matcher, $workspace);
            $results[] = $current;
            if ($current->result->status !== SolveStatus::Conflict) {
                break;
            }
        }

        return $results;
    }

    /**
     * @param list<string> $alreadyListed
     *
     * @return list<string>
     */
    private static function lockedBlockers(string $solverOutput, array $alreadyListed, string $vulnerablePackage): array
    {
        if (preg_match_all('{- ([a-z0-9_.-]+/[a-z0-9_.-]+) is locked to version \S+ and an update of this package was not requested}i', $solverOutput, $m) === 0) {
            return [];
        }
        $blockers = [];
        foreach (array_unique(array_map('strtolower', $m[1])) as $name) {
            if ($name !== $vulnerablePackage && !in_array($name, $alreadyListed, true)) {
                $blockers[] = $name;
            }
        }

        return $blockers;
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
        if (!in_array($candidate->strategy, [Strategy::ParentUpdate, Strategy::RootConstraintWiden], true) || $candidate->allowList === [] || $candidate->pins !== [] || $start->result->after === null) {
            return [];
        }
        // Descend on the parent the candidate started from; siblings added by conflict expansion follow it.
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
