<?php

declare(strict_types=1);

namespace Remediate\Engine;

use Composer\DependencyResolver\Request;
use Composer\Semver\Comparator;
use Composer\Semver\Constraint\ConstraintInterface;
use Composer\Semver\Constraint\MultiConstraint;
use Remediate\Engine\Advisory\AdvisoryProvider;
use Remediate\Engine\Advisory\CoverageAware;
use Remediate\Engine\Candidate\Candidate;
use Remediate\Engine\Candidate\CandidateGenerator;
use Remediate\Engine\Candidate\FixedRangeResolver;
use Remediate\Engine\Candidate\Strategy;
use Remediate\Engine\Graph\DependencyGraph;
use Remediate\Engine\Lock\LockSnapshot;
use Remediate\Engine\Matching\Finding;
use Remediate\Engine\Matching\IgnorePolicy;
use Remediate\Engine\Matching\Matcher;
use Remediate\Engine\Plan\CombinedAttempt;
use Remediate\Engine\Plan\CombinedOutcome;
use Remediate\Engine\Plan\CombinedRemediation;
use Remediate\Engine\Plan\CombinedSearch;
use Remediate\Engine\Plan\EvaluatedCandidate;
use Remediate\Engine\Plan\FindingPlan;
use Remediate\Engine\Plan\Plan;
use Remediate\Engine\Project\ProjectContext;
use Remediate\Engine\Ranking\Ranker;
use Remediate\Engine\Solver\LockDiff;
use Remediate\Engine\Solver\ReleaseAgeGuard;
use Remediate\Engine\Solver\ScratchWorkspace;
use Remediate\Engine\Solver\SolveResult;
use Remediate\Engine\Solver\SolveStatus;
use Remediate\Engine\Solver\SolverInterface;

final class Planner
{
    /** Maximum number of downward probes when searching for the lowest working parent version. */
    public const MAX_DESCENT_STEPS = 6;

    /** Maximum number of times a conflicting candidate is widened with the locked packages Composer names as blockers. */
    public const MAX_EXPANSIONS = 8;

    /** Default ceiling on solver invocations per finding, all phases included (candidates, expansion, descent, simplification). */
    public const DEFAULT_SOLVE_BUDGET = 60;

    /** Solves held back from the search so the winner's simplification (at most three variants) can always run. */
    public const SIMPLIFY_RESERVE = 3;

    /** @var callable(string): void|null */
    private $progress;

    private int $totalSolves = 0;

    private int $findingSolves = 0;

    private bool $budgetExhausted = false;

    /**
     * @param IgnorePolicy|null    $ignore      advisories to leave out (ids, CVEs, package rules)
     * @param ReleaseAgeGuard|null $releaseAge  reject candidates that install releases younger than a cooldown
     * @param int                  $solveBudget hard ceiling on solver runs per finding; every phase of the search counts
     * @param bool                 $acceptCoverageGaps a candidate that adds a package whose advisory records the source could
     *                                                 not read is rejected by default (the new package cannot be vouched
     *                                                 for); with this, it is accepted and the gaps are reported with it
     */
    public function __construct(
        private readonly AdvisoryProvider $advisories,
        private readonly SolverInterface $solver,
        private readonly CandidateGenerator $generator = new CandidateGenerator(),
        private readonly bool $includeDev = true,
        private readonly int $maxCandidatesPerFinding = 10,
        ?callable $progress = null,
        private readonly ?IgnorePolicy $ignore = null,
        private readonly ?ReleaseAgeGuard $releaseAge = null,
        private readonly int $solveBudget = self::DEFAULT_SOLVE_BUDGET,
        private readonly bool $acceptCoverageGaps = false,
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
        $this->totalSolves = 0;
        $lock = $context->lockSnapshot();
        $graph = new DependencyGraph($context->rootPackage(), $context->lockedRepository());
        $matcher = (new Matcher($this->advisories))->withIgnorePolicy($this->ignore ?? IgnorePolicy::none());
        $isRoot = static fn (string $name): bool => $context->isRootRequirement($name);
        $ranker = new Ranker($isRoot);
        $warnings = [];

        if (!$this->advisories->isComplete()) {
            $warnings[] = sprintf('Advisory source "%s" only knows advisories for the current lock; a candidate lock cannot be checked for other advisories, so no remediation is verified or recommended. Use a complete source: --database-location or a full Packagist snapshot.', $this->advisories->describe());
        }

        $allFindings = $matcher->match($lock, $isRoot);
        $coverageGaps = [];
        if ($this->advisories instanceof CoverageAware) {
            // Records the source could not read are not evidence of safety: they are reported next to
            // the result and, unless the operator accepts them, keep a lock without findings from
            // exiting clean. Replaced and provided names count, since advisories reach them too.
            $coverageGaps = $this->advisories->coverageWarnings(Matcher::queriedNames($lock));
            array_push($warnings, ...$coverageGaps);
        }
        if ($matcher->ignoredCount() > 0) {
            $warnings[] = sprintf('%d advisory match%s ignored per configuration (--ignore, config.audit.ignore or config.policy).', $matcher->ignoredCount(), $matcher->ignoredCount() === 1 ? '' : 'es');
        }
        $unused = $matcher->unusedIgnores();
        if ($unused !== []) {
            $warnings[] = sprintf('Ignore hygiene: %d ignore entr%s match%s nothing in this lock and can be removed: %s.', count($unused), count($unused) === 1 ? 'y' : 'ies', count($unused) === 1 ? 'es' : '', implode(', ', $unused));
        }
        // The baseline is every advisory present before remediation, development ones included even
        // under --no-dev: an untouched dev vulnerability in a candidate lock is not "newly introduced".
        $baseline = [];
        foreach ($allFindings as $finding) {
            $baseline[$finding->key()] = true;
        }
        $findings = $this->includeDev ? $allFindings : array_values(array_filter($allFindings, static fn (Finding $f): bool => !$f->isDev));
        // Production findings first, development-only findings after them; within each, the most urgent
        // package first (known exploited, then exploit probability, then severity), so the top of the
        // report is what to fix today. A package's urgency is that of its most urgent advisory.
        $urgency = [];
        foreach ($findings as $finding) {
            $key = $finding->advisory->urgency();
            $urgency[$finding->packageName] = isset($urgency[$finding->packageName]) ? min($urgency[$finding->packageName], $key) : $key;
        }
        usort($findings, static fn (Finding $a, Finding $b): int => [$a->isDev ? 1 : 0, $urgency[$a->packageName], $a->packageName, $a->advisory->id] <=> [$b->isDev ? 1 : 0, $urgency[$b->packageName], $b->packageName, $b->advisory->id]);

        // Several advisories on one package are remediated together: one command must escape all of them.
        $groups = [];
        foreach ($findings as $finding) {
            $groups[$finding->packageName][] = $finding;
        }

        $plans = [];
        foreach ($groups as $group) {
            $plans[] = $this->planGroup($group, $graph, $context, $lock, $baseline, $matcher, $ranker, $workspace);
        }

        [$combined, $combinedAttempts] = $this->combine($plans, $lock, $baseline, $matcher, $workspace);

        foreach ($plans as $plan) {
            $recommended = $plan->recommended();
            if ($recommended !== null && $recommended->blockingRisk !== []) {
                $warnings[] = sprintf('%s: the recommended command moves %s to a version that still carries another advisory; Composer 2.10+ advisory blocking may refuse it until that advisory is ignored in config.policy or blocking is disabled.', $plan->finding->packageName, implode(', ', $recommended->blockingRisk));
            }
        }

        return new Plan($plans, [
            'project' => $context->directory,
            'engine_version' => self::engineVersion(),
            'composer_version' => $context->composerVersion(),
            'php_version' => PHP_VERSION,
            'advisory_source' => $this->advisories->describe(),
            'solver' => $this->solver->describe(),
            'solver_runs' => (string) $this->totalSolves,
            'composer_json_sha256' => self::fileHash($context->composerJsonPath()),
            'composer_lock_sha256' => self::fileHash($context->lockPath()),
            'analysis_timestamp' => gmdate('c'),
            'locked_packages' => (string) $lock->count(),
        ], $warnings, $combined, null, self::inventory($lock), [], array_values(array_unique([...$coverageGaps, ...self::acceptedGapsOf($plans, $combined)])), false, $combinedAttempts);
    }

    /**
     * Packages Packagist marks abandoned among the vulnerable package and its dependency paths: an
     * abandoned parent will not ship the release that lifts its pin, and an abandoned vulnerable
     * package will not ship a fix.
     *
     * @return array<string, string|null> package => replacement package, or null when none is named
     */
    private static function abandonedOnPaths(Finding $finding, LockSnapshot $lock): array
    {
        $names = [$finding->packageName];
        foreach ($finding->paths as $path) {
            foreach ($path->segments as $segment) {
                if (!$segment->isRoot) {
                    $names[] = $segment->packageName;
                }
            }
        }
        $abandoned = [];
        foreach (array_unique($names) as $name) {
            $package = $lock->get($name);
            if ($package instanceof \Composer\Package\CompletePackageInterface && $package->isAbandoned()) {
                $abandoned[$package->getName()] = $package->getReplacementPackage();
            }
        }
        ksort($abandoned);

        return $abandoned;
    }

    /**
     * @param non-empty-list<Finding> $group
     * @param array<string, true>     $baseline
     */
    private function planGroup(array $group, DependencyGraph $graph, ProjectContext $context, LockSnapshot $lock, array $baseline, Matcher $matcher, Ranker $ranker, ScratchWorkspace $workspace): FindingPlan
    {
        $this->findingSolves = 0;
        $this->budgetExhausted = false;
        $finding = $group[0]->withPaths($graph->pathsToRoot($group[0]->packageName));
        $finding = $finding->withAbandoned(self::abandonedOnPaths($finding, $lock));
        $related = array_slice($group, 1);
        if (!$this->advisories->isComplete()) {
            // A source that only knows the current lock's advisories cannot say whether a candidate lock
            // is clean; recommending anyway would be a fix verified against nothing. Fail closed.
            return new FindingPlan($finding, [], [], sprintf('Advisory source "%s" only knows the advisories of the current lock; a candidate lock cannot be checked for other advisories, so no remediation can be verified. Use a complete source (--database-location, or a full Packagist snapshot with --advisories-file).', $this->advisories->describe()), [], $related);
        }
        $groupKeys = [];
        foreach ($group as $member) {
            $groupKeys[$member->key()] = true;
        }
        // The fixed range must escape every advisory known for this package, not only the ones hitting
        // the locked version: a newer release affected by a different advisory is not a fix either.
        $affected = $this->affectedUnion($finding->packageName, $group, $finding->version);
        $this->report(sprintf('%s on %s %s', implode(', ', array_map(static fn (Finding $f): string => $f->advisory->displayId(), $group)), $finding->packageName, $finding->prettyVersion));

        $candidates = $this->generator->generate($finding, $graph, $context->rootRequirements(), $affected);
        if ($candidates === []) {
            return new FindingPlan($finding, [], [], sprintf('No release of %s newer than %s is outside the affected range %s.', $finding->packageName, $finding->prettyVersion, $affected->getPrettyString()), [], $related);
        }

        $evaluated = [];
        $skipped = [];
        $seen = [];
        $truncated = count($candidates) > $this->maxCandidatesPerFinding;
        foreach (array_slice($candidates, 0, $this->maxCandidatesPerFinding) as $candidate) {
            if ($this->budgetExhausted) {
                $skipped[] = $candidate;
                continue;
            }
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

        $ranked = $ranker->rank($evaluated);
        if ($ranked !== []) {
            $ranked[0] = $this->simplify($ranked[0], $finding, $groupKeys, $lock, $baseline, $matcher, $workspace);
        }

        $infrastructure = null;
        $blocker = null;
        if ($ranked === []) {
            // Without a verified fix, any solve that failed for tool or network reasons makes the
            // outcome unknown rather than "no fix exists".
            foreach ($evaluated as $e) {
                if ($e->result->status === SolveStatus::Error) {
                    $infrastructure = SolveStatus::Error;
                    break;
                }
                if ($e->result->status === SolveStatus::Transport) {
                    $infrastructure = SolveStatus::Transport;
                }
            }
            if ($infrastructure === SolveStatus::Transport) {
                $blocker = 'At least one solve failed with a network error; package metadata could not be fetched, so the absence of a fix is not established.';
            } elseif ($infrastructure === SolveStatus::Error) {
                $blocker = 'At least one solve failed inside Composer; the absence of a fix is not established.';
            } elseif ($truncated || $this->budgetExhausted) {
                $blocker = sprintf('No verified fix within the search budget (%d candidate%s tried, %d solver run%s); a fix outside the bounded search may still exist.', count($evaluated), count($evaluated) === 1 ? '' : 's', $this->findingSolves, $this->findingSolves === 1 ? '' : 's');
            }
        }

        return new FindingPlan($finding, $evaluated, $ranked, $blocker, $skipped, $related, $infrastructure, $truncated || $this->budgetExhausted, $this->findingSolves);
    }

    /**
     * Union of the affected ranges of every non-ignored advisory the source knows for the package.
     *
     * @param non-empty-list<Finding> $group
     */
    private function affectedUnion(string $packageName, array $group, string $normalizedVersion): ConstraintInterface
    {
        $ranges = [];
        $ids = [];
        foreach ($group as $member) {
            $ranges[] = $member->advisory->affectedVersions;
            $ids[$member->advisory->id] = true;
        }
        $policy = $this->ignore ?? IgnorePolicy::none();
        try {
            $known = $this->advisories->advisoriesFor([$packageName])[$packageName] ?? [];
        } catch (\Throwable) {
            $known = []; // the matcher already fetched this package's advisories; a second failure changes nothing
        }
        foreach ($known as $advisory) {
            if (isset($ids[$advisory->id]) || $policy->matchedEntry($advisory->id, $advisory->cve, $packageName, $normalizedVersion) !== null) {
                continue;
            }
            $ranges[] = $advisory->affectedVersions;
        }

        return count($ranges) === 1 ? $ranges[0] : MultiConstraint::create($ranges, false);
    }

    /**
     * @return list<array{name: string, version: string, dev: bool}>
     */
    private static function inventory(LockSnapshot $lock): array
    {
        $inventory = [];
        foreach ($lock->packages as $name => $package) {
            $inventory[] = ['name' => $name, 'version' => $package->getPrettyVersion(), 'dev' => $lock->isDev($name)];
        }

        return $inventory;
    }

    /**
     * Solves the global search may spend beyond the first merge of the per-package winners; the
     * per-finding --solve-budget caps it too, since the search counts as one more finding.
     */
    public const GLOBAL_SOLVE_BUDGET = 10;

    /**
     * Global planning: find one command that fixes every finding, with as little change as possible.
     *
     * The per-package winners are merged and verified with one solve. When that does not fix
     * everything, repair() swaps in next-ranked candidates within a solve budget; a combination that
     * fixes everything is then passed to shrink(). Every step is recorded so the report can say why the
     * recommended command is what it is. The acceptance rules for individual candidates apply
     * throughout: no new advisories, no release younger than the cooldown.
     *
     * @param list<FindingPlan>   $plans
     * @param array<string, true> $baseline
     *
     * @return array{?CombinedRemediation, list<CombinedAttempt>}
     */
    private function combine(array $plans, LockSnapshot $lock, array $baseline, Matcher $matcher, ScratchWorkspace $workspace): array
    {
        $search = CombinedSearch::over($plans);
        if ($search === null) {
            return [null, []];
        }
        if ($search->contributorCount() === 1) {
            return [self::soleContribution($search, $matcher), []];
        }

        $this->findingSolves = 0;
        $this->budgetExhausted = false;
        $verify = fn (Candidate $c): CombinedRemediation|array => $this->acceptCombined($c, $lock, $baseline, $search->allKeys, $matcher, $workspace);

        $search->adoptIfBetter($this->tryCombination($search, $search->bestChoice, 'per-package winners merged', $verify), $search->bestChoice);
        $this->repair($search, $verify);
        $this->shrink($search, $verify);
        $search->markChosen();

        $best = $search->best;
        if ($best === null) {
            return [null, $search->attempts];
        }
        // Prefer the simplest spelling that yields the identical lock; it is re-matched and re-diffed
        // rather than inheriting the original's bookkeeping.
        foreach (self::simplerVariants($best->candidate) as $variant) {
            $simpler = $verify($variant);
            if ($simpler instanceof CombinedRemediation && $best->result->after !== null && $simpler->result->after !== null && self::sameLock($simpler->result->after, $best->result->after)) {
                return [$simpler, $search->attempts];
            }
        }

        return [$best, $search->attempts];
    }

    /**
     * Coverage gaps the recommended commands would introduce (only present when the operator accepted
     * gaps); they join the plan's gaps so the report and the JSON summary list them.
     *
     * @param list<FindingPlan> $plans
     *
     * @return list<string>
     */
    private static function acceptedGapsOf(array $plans, ?CombinedRemediation $combined): array
    {
        $gaps = $combined === null ? [] : $combined->coverageGaps;
        foreach ($plans as $plan) {
            $recommended = $plan->recommended();
            if ($recommended !== null) {
                array_push($gaps, ...$recommended->coverageGaps);
            }
        }

        return $gaps;
    }

    /** With one contributing plan there is nothing to merge: its winner is the combined command. */
    private static function soleContribution(CombinedSearch $search, Matcher $matcher): ?CombinedRemediation
    {
        $winner = $search->soleWinner();
        if ($winner->result->after === null || $winner->diff === null) {
            return null;
        }
        $afterKeys = $matcher->findingKeys($winner->result->after);

        return new CombinedRemediation($winner->candidate, $winner->result, $winner->diff, array_keys(array_diff_key($search->allKeys, $afterKeys)), array_keys(array_intersect_key($search->allKeys, $afterKeys)), $winner->coverageGaps);
    }

    /**
     * Solves one combination, records the attempt, and returns the remediation when it resolves and
     * passes the acceptance rules. Null when it was already tried or the budget is spent.
     *
     * @param array<int, int>                                                              $choice
     * @param callable(Candidate): (CombinedRemediation|array{CombinedOutcome, string}) $verify
     */
    private function tryCombination(CombinedSearch $search, array $choice, string $note, callable $verify): ?CombinedRemediation
    {
        if (!$this->globalBudgetLeft()) {
            return null;
        }
        $merged = $search->merged($choice);
        if ($merged === null) {
            return null;
        }
        $this->report('combining: ' . $merged->commandLine($this->solver->supportsMinimalChanges()) . ' (' . $note . ')');
        $outcome = $verify($merged);
        if ($outcome instanceof CombinedRemediation) {
            $search->record(new CombinedAttempt($merged, $outcome->fixesAll() ? CombinedOutcome::Accepted : CombinedOutcome::Partial, $note, $outcome->fixedCount(), $outcome->totalCount(), $outcome->fixesAll() ? null : sprintf('leaves %s', implode(', ', $outcome->unfixedKeys))));

            return $outcome;
        }
        [$kind, $reason] = $outcome;
        $search->record(new CombinedAttempt($merged, $kind, $note, 0, count($search->allKeys), $reason));

        return null;
    }

    /**
     * Repair: while the best combination does not fix everything, swap in the next-ranked candidate
     * of a finding that stands in the way (named in the solver output, or left unfixed), one at a
     * time, keeping any swap that fixes more or as much with a smaller diff.
     *
     * @param callable(Candidate): (CombinedRemediation|array{CombinedOutcome, string}) $verify
     */
    private function repair(CombinedSearch $search, callable $verify): void
    {
        while (!$search->fixesAll() && $this->globalBudgetLeft()) {
            $progress = false;
            foreach ($search->plansInTheWay() as $index) {
                $current = $search->bestChoice[$index];
                if (!isset($search->ranked[$index][$current + 1])) {
                    continue;
                }
                $choice = $search->bestChoice;
                $choice[$index] = $current + 1;
                $result = $this->tryCombination($search, $choice, sprintf('%s: candidate ranked %d instead of %d', $search->packageOf($index), $current + 2, $current + 1), $verify);
                if ($search->adoptIfBetter($result, $choice)) {
                    $progress = true;
                    break;
                }
            }
            if (!$progress) {
                break;
            }
        }
    }

    /**
     * Shrink: a command fixing everything may carry contributions another finding's fix already
     * covers. Each contribution whose vulnerable package a sibling's own solve moves is dropped in
     * turn; the smaller command is kept when it still fixes everything with no larger a diff. Every
     * solve here costs a full dry run, so contributions nothing else moves are not tried.
     *
     * @param callable(Candidate): (CombinedRemediation|array{CombinedOutcome, string}) $verify
     */
    private function shrink(CombinedSearch $search, callable $verify): void
    {
        if (!$search->fixesAll()) {
            return;
        }
        $active = $search->bestChoice;
        $shrunk = true;
        while ($shrunk && count($active) > 1 && $this->globalBudgetLeft()) {
            $shrunk = false;
            foreach ($search->droppable($active) as $index) {
                $without = $active;
                unset($without[$index]);
                $result = $this->tryCombination($search, $without, sprintf('without the command for %s', $search->packageOf($index)), $verify);
                if ($result !== null && $result->fixesAll() && $search->best !== null && $result->diff->count() <= $search->best->diff->count()) {
                    $search->best = $result;
                    $search->bestChoice = $without;
                    $active = $without;
                    $shrunk = true;
                    break;
                }
            }
        }
    }

    /** Whether the global search may spend another solve: its own ceiling and the --solve-budget both apply. */
    private function globalBudgetLeft(): bool
    {
        return !$this->budgetExhausted && $this->findingSolves <= self::GLOBAL_SOLVE_BUDGET;
    }

    /**
     * Solves a merged command and applies the acceptance rules. Returns the remediation, or the kind
     * of failure with the solver's or the rule's explanation.
     *
     * @param array<string, true> $baseline
     * @param array<string, true> $allKeys
     *
     * @return CombinedRemediation|array{CombinedOutcome, string}
     */
    private function acceptCombined(Candidate $candidate, LockSnapshot $lock, array $baseline, array $allKeys, Matcher $matcher, ScratchWorkspace $workspace): CombinedRemediation|array
    {
        $result = $this->solve($candidate, $workspace, true);
        if (!$result->resolved() || $result->after === null) {
            return [CombinedOutcome::Unresolved, $result->status === SolveStatus::Conflict ? $result->explanation() : self::describeFailure($result->status)];
        }
        $afterKeys = $matcher->findingKeys($result->after);
        $introduced = array_keys(array_diff_key($afterKeys, $baseline));
        if ($introduced !== []) {
            return [CombinedOutcome::Rejected, 'introduces new advisories: ' . implode(', ', $introduced)];
        }
        $diff = LockDiff::between($lock, $result->after);
        if ($this->releaseAge !== null) {
            $young = $this->releaseAge->tooYoung($diff, $result->after);
            if ($young !== []) {
                return [CombinedOutcome::Rejected, 'installs releases younger than the minimum release age: ' . implode(', ', $young)];
            }
        }
        $gaps = $this->introducedCoverageGaps($lock, $result->after);
        if ($gaps !== [] && !$this->acceptCoverageGaps) {
            return [CombinedOutcome::Rejected, 'adds packages whose advisory records the source could not read: ' . implode(' ', $gaps)];
        }
        $fixed = array_keys(array_diff_key($allKeys, $afterKeys));
        $unfixed = array_keys(array_intersect_key($allKeys, $afterKeys));

        return new CombinedRemediation($candidate, $result, $diff, $fixed, $unfixed, $gaps);
    }

    /** @return list<Candidate> */
    private static function simplerVariants(Candidate $c): array
    {
        $variants = [];
        if ($c->temporaryConstraints !== [] && $c->minimalChanges) {
            $variants[] = $c->simplified(true, true);
        }
        if ($c->temporaryConstraints !== []) {
            $variants[] = $c->simplified(true, false);
        }
        if ($c->minimalChanges) {
            $variants[] = $c->simplified(false, true);
        }

        return $variants;
    }

    /**
     * The temporary constraint and -m exist to steer the solver; a human types neither when the plain
     * command already produces the same lock. Try the simpler spellings and keep the simplest one
     * that yields exactly the same lock.
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
        foreach (self::simplerVariants($c) as $variant) {
            if ($this->findingSolves >= $this->solveBudget) {
                break;
            }
            $evaluation = $this->evaluate($variant, $finding, $groupKeys, $lock, $baseline, $matcher, $workspace, true);
            if ($evaluation->valid && $evaluation->result->after !== null && self::sameLock($evaluation->result->after, $winner->result->after)) {
                return $evaluation;
            }
        }

        return $winner;
    }

    /**
     * Two locks are the same when every package has the same version, the same source and dist
     * references (two dev-main checkouts at different commits are different locks) and the same
     * production/development classification.
     */
    public static function sameLock(LockSnapshot $a, LockSnapshot $b): bool
    {
        if ($a->names() !== $b->names()) {
            return false;
        }
        foreach ($a->packages as $name => $package) {
            $other = $b->get($name);
            if ($other === null
                || $other->getVersion() !== $package->getVersion()
                || $other->getSourceReference() !== $package->getSourceReference()
                || $other->getDistReference() !== $package->getDistReference()
                || $a->isDev($name) !== $b->isDev($name)) {
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
     * Every solver invocation goes through here so the per-finding budget and the totals are exact.
     * The search phases (candidates, expansion, descent) stop SIMPLIFY_RESERVE solves early so the
     * winner's simplification is never starved by a long descent on a worse parent.
     */
    private function solve(Candidate $candidate, ScratchWorkspace $workspace, bool $simplifying = false): SolveResult
    {
        $limit = $simplifying ? $this->solveBudget : max(1, $this->solveBudget - self::SIMPLIFY_RESERVE);
        if ($this->findingSolves >= $limit) {
            $this->budgetExhausted = true;

            return new SolveResult(SolveStatus::Conflict, null, '', sprintf('not solved: the budget of %d solver runs for this finding is used up', $this->solveBudget));
        }
        ++$this->findingSolves;
        ++$this->totalSolves;
        $result = $this->solver->solve($candidate, $workspace);
        if ($this->findingSolves >= $limit) {
            $this->budgetExhausted = true;
        }

        return $result;
    }

    /**
     * @param array<string, true> $groupKeys finding keys this candidate must remove
     * @param array<string, true> $baseline  finding keys present before remediation
     */
    private function evaluate(Candidate $candidate, Finding $finding, array $groupKeys, LockSnapshot $lock, array $baseline, Matcher $matcher, ScratchWorkspace $workspace, bool $simplifying = false): EvaluatedCandidate
    {
        $this->report('  trying ' . $candidate->commandLine($this->solver->supportsMinimalChanges()));
        $result = $this->solve($candidate, $workspace, $simplifying);

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
        if ($this->releaseAge !== null) {
            $young = $this->releaseAge->tooYoung($diff, $result->after);
            if ($young !== []) {
                return new EvaluatedCandidate($candidate, $result, $diff, false, 'resolves, but installs releases younger than the minimum release age: ' . implode(', ', $young));
            }
        }
        $gaps = $this->introducedCoverageGaps($lock, $result->after);
        if ($gaps !== [] && !$this->acceptCoverageGaps) {
            return new EvaluatedCandidate($candidate, $result, $diff, false, 'resolves, but adds packages whose advisory records the source could not read, so they cannot be vouched for (pass --accept-coverage-gaps to allow this): ' . implode(' ', $gaps));
        }

        return new EvaluatedCandidate($candidate, $result, $diff, true, null, self::blockingRisk($diff, $afterKeys), $gaps);
    }

    /**
     * Coverage-gap warnings about packages the candidate lock adds (or newly replaces or provides):
     * the source read the records about the locked packages, but not about these, so a "verified"
     * result could hide an advisory on a package the fix itself brought in.
     *
     * @return list<string>
     */
    private function introducedCoverageGaps(LockSnapshot $before, LockSnapshot $after): array
    {
        if (!$this->advisories instanceof CoverageAware) {
            return [];
        }
        $new = array_values(array_diff(Matcher::queriedNames($after), Matcher::queriedNames($before)));
        if ($new === []) {
            return [];
        }

        return $this->advisories->coverageWarnings($new);
    }

    /**
     * Packages this command changes whose new version still carries an advisory (one that was already
     * present, so the candidate is not rejected). Composer 2.10+ blocks such updates by default.
     *
     * @param array<string, true> $afterKeys
     *
     * @return list<string>
     */
    private static function blockingRisk(LockDiff $diff, array $afterKeys): array
    {
        $stillVulnerable = [];
        foreach (array_keys($afterKeys) as $key) {
            $stillVulnerable[explode('@', $key, 2)[1] ?? ''] = true;
        }
        $risk = [];
        foreach ($diff->changes as $change) {
            if ($change->kind !== \Remediate\Engine\Solver\PackageChange::REMOVED && isset($stillVulnerable[$change->packageName])) {
                $risk[] = $change->packageName;
            }
        }

        return $risk;
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
        for ($step = 0; $step < self::MAX_EXPANSIONS && !$this->budgetExhausted; ++$step) {
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
     * Probes count towards the solve budget and total; only the pinned result joins the ranking.
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
        for ($step = 0; $step < self::MAX_DESCENT_STEPS && !$this->budgetExhausted; ++$step) {
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

        if ($best === null || $this->budgetExhausted) {
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
