<?php

declare(strict_types=1);

namespace Remediate\Engine\Plan;

use Remediate\Engine\Advisory\Severity;
use Remediate\Engine\Solver\SolveStatus;

final class Plan
{
    public const EXIT_CLEAN = 0;
    public const EXIT_REMEDIATION_AVAILABLE = 1;
    public const EXIT_NO_REMEDIATION = 2;
    public const EXIT_ERROR = 3;
    public const EXIT_ADVISORIES_UNAVAILABLE = 4;
    public const EXIT_SOLVER_FAILURE = 5;

    /**
     * @param list<FindingPlan>     $findings
     * @param array<string, string> $metadata
     * @param list<string>          $warnings
     */

    /**
     * @param list<FindingPlan>     $findings
     * @param array<string, string> $metadata
     * @param list<string>          $warnings
     * @param string|null           $failOn    severity threshold for the exit code: findings whose advisories are all
     *                                         below it do not affect the exit code (unknown severity always counts)
     * @param list<array{name: string, version: string, dev: bool}> $inventory every locked package, for SBOM output
     * @param array<string, true> $baseline finding keys (advisory@package) accepted earlier; they are reported but do not affect the exit code
     * @param list<CombinedAttempt> $combinedAttempts the global search for one command fixing everything, step by step
     * @param list<string> $coverageGaps advisory records about locked packages the advisory source could not read: the
     *                                   lock may be affected by an advisory the source cannot express. Unless accepted,
     *                                   a lock with gaps and no findings exits 4 (advisory data unavailable), not 0.
     */
    public function __construct(
        public readonly array $findings,
        public readonly array $metadata,
        public readonly array $warnings = [],
        public readonly ?CombinedRemediation $combined = null,
        public readonly ?string $failOn = null,
        public readonly array $inventory = [],
        public readonly array $baseline = [],
        public readonly array $coverageGaps = [],
        public readonly bool $coverageGapsAccepted = false,
        public readonly array $combinedAttempts = [],
        /**
         * A terminal failure this run hit before it could produce findings, as the exit code that
         * describes it. Set, it *is* the exit code: there is nothing to gate on, and every format asks
         * ScanOutcome, so a report built from this plan says the run did not complete rather than
         * showing an empty vulnerability list that reads as clean.
         */
        public readonly ?int $failure = null,
        /**
         * Package names the operator declared exposed with --exposed: they handle untrusted input in
         * this application. Only withExposure() sets it, on a finished plan, so a declaration can
         * reorder the report and never change what was planned or recommended.
         *
         * @var array<string, true>
         */
        public readonly array $exposed = [],
    ) {
    }

    /**
     * The plan for a run that failed before it could look: advisory data that could not be read, an
     * apply that Composer refused. It exists so the failure still goes through the renderers, because
     * a run that writes no report leaves the last successful one on disk for a CI step to publish.
     *
     * @param array<string, string> $metadata
     * @param list<string>          $warnings
     */
    public static function failed(int $exitCode, array $metadata = [], array $warnings = []): self
    {
        return new self([], $metadata, $warnings, null, null, [], [], [], false, [], $exitCode, []);
    }

    /**
     * The same plan, reported as a run that could not answer. Its findings and recommendations stay:
     * what changes is that the exit code, and every format that asks ScanOutcome, stop calling it a
     * completed run.
     */
    public function withFailure(int $exitCode): self
    {
        return new self($this->findings, $this->metadata, $this->warnings, $this->combined, $this->failOn, $this->inventory, $this->baseline, $this->coverageGaps, $this->coverageGapsAccepted, $this->combinedAttempts, $exitCode, $this->exposed);
    }

    /** The caller has read the coverage gaps and accepts the lock as clean despite them (--accept-coverage-gaps). */
    public function withAcceptedCoverageGaps(): self
    {
        return new self($this->findings, $this->metadata, $this->warnings, $this->combined, $this->failOn, $this->inventory, $this->baseline, $this->coverageGaps, true, $this->combinedAttempts, $this->failure, $this->exposed);
    }

    public function withFailOn(?string $severity): self
    {
        if ($severity !== null && Severity::fromLabel($severity) === null) {
            throw new \InvalidArgumentException(sprintf('Unknown severity "%s"; use one of %s.', $severity, Severity::labels()));
        }

        return new self($this->findings, $this->metadata, $this->warnings, $this->combined, $severity !== null ? strtolower($severity) : null, $this->inventory, $this->baseline, $this->coverageGaps, $this->coverageGapsAccepted, $this->combinedAttempts, $this->failure, $this->exposed);
    }

    /** @param list<string> $keys finding keys (advisory@package) */
    public function withBaseline(array $keys): self
    {
        $baseline = [];
        foreach ($keys as $key) {
            $baseline[strtolower($key)] = true;
        }

        return new self($this->findings, $this->metadata, $this->warnings, $this->combined, $this->failOn, $this->inventory, $baseline, $this->coverageGaps, $this->coverageGapsAccepted, $this->combinedAttempts, $this->failure, $this->exposed);
    }

    /**
     * The same plan with packages declared exposed (--exposed): production findings on them are listed
     * first, then the other production findings, then development-only ones, each group keeping the
     * urgency order the planner gave it. A declaration is the operator's knowledge of the application,
     * which no advisory feed has, so it outranks known exploitation; it is never inferred.
     *
     * It is applied to the finished plan, so it cannot change a recommendation, the combined command or
     * the exit code. A name that is not in the lock is reported, as it is most likely a typo.
     *
     * @param list<string> $packages
     */
    public function withExposure(array $packages): self
    {
        $exposed = [];
        foreach ($packages as $package) {
            $exposed[strtolower(trim($package))] = true;
        }
        unset($exposed['']);
        $warnings = $this->warnings;
        if ($exposed !== [] && $this->inventory !== []) {
            $locked = array_fill_keys(array_map(static fn (array $p): string => strtolower($p['name']), $this->inventory), true);
            $unknown = array_keys(array_diff_key($exposed, $locked));
            if ($unknown !== []) {
                $warnings[] = sprintf('--exposed names %s, which %s not in this lock.', implode(', ', $unknown), count($unknown) === 1 ? 'is' : 'are');
            }
        }
        $keyed = [];
        foreach ($this->findings as $index => $plan) {
            $keyed[] = [$plan->finding->isDev ? 2 : (self::exposedIn($exposed, $plan) ? 0 : 1), $index, $plan];
        }
        usort($keyed, static fn (array $a, array $b): int => [$a[0], $a[1]] <=> [$b[0], $b[1]]);
        $findings = array_column($keyed, 2);

        return new self($findings, $this->metadata, $warnings, $this->combined, $this->failOn, $this->inventory, $this->baseline, $this->coverageGaps, $this->coverageGapsAccepted, $this->combinedAttempts, $this->failure, $exposed);
    }

    /** Whether the operator declared this finding's package, or the package it stands in for, exposed. */
    public function isExposed(FindingPlan $plan): bool
    {
        return self::exposedIn($this->exposed, $plan);
    }

    /** @return list<FindingPlan> */
    public function exposedFindings(): array
    {
        return array_values(array_filter($this->findings, fn (FindingPlan $p): bool => $this->isExposed($p)));
    }

    /** @param array<string, true> $exposed */
    private static function exposedIn(array $exposed, FindingPlan $plan): bool
    {
        $f = $plan->finding;

        return isset($exposed[strtolower($f->packageName)]) || ($f->viaReplacedName !== null && isset($exposed[strtolower($f->viaReplacedName)]));
    }

    /** True when every advisory of the finding is in the baseline. */
    public function isBaselined(FindingPlan $plan): bool
    {
        if ($this->baseline === []) {
            return false;
        }
        foreach ($plan->allFindings() as $finding) {
            if (!isset($this->baseline[strtolower($finding->key())])) {
                return false;
            }
        }

        return true;
    }

    /** @return list<FindingPlan> */
    public function baselined(): array
    {
        return array_values(array_filter($this->findings, fn (FindingPlan $p): bool => $this->isBaselined($p)));
    }

    /**
     * All finding keys of this plan, the content of a baseline that accepts everything currently found.
     *
     * @return list<string>
     */
    public function findingKeys(): array
    {
        $keys = [];
        foreach ($this->findings as $plan) {
            foreach ($plan->allFindings() as $finding) {
                $keys[] = $finding->key();
            }
        }
        sort($keys);

        return $keys;
    }

    /**
     * Whether a package counts towards the exit code under the severity threshold and the baseline.
     *
     * Both tests apply to the same individual advisory, and that is the whole of the rule. Asking
     * whether the package as a whole was accepted and then asking whether any of its advisories meets
     * the threshold answers about two different sets: an accepted advisory would go on gating the run
     * through a severity it was accepted at, as soon as anything else on that package was not
     * accepted. An advisory gates only if it was not accepted and it meets the threshold.
     */
    public function countsForExit(FindingPlan $plan): bool
    {
        $threshold = $this->failOn === null ? null : (Severity::fromLabel($this->failOn)?->rank() ?? 0);
        foreach ($plan->allFindings() as $finding) {
            if ($this->baseline !== [] && isset($this->baseline[strtolower($finding->key())])) {
                continue;
            }
            if ($threshold === null) {
                return true;
            }
            $rank = Severity::fromLabel($finding->advisory->severity)?->rank();
            // Missing or unrecognised severities are unknown, and unknown always counts.
            if ($rank === null || $rank >= $threshold) {
                return true;
            }
        }

        return false;
    }

    /** @param list<string> $warnings */
    public function withWarnings(array $warnings): self
    {
        return new self($this->findings, $this->metadata, [...$this->warnings, ...$warnings], $this->combined, $this->failOn, $this->inventory, $this->baseline, $this->coverageGaps, $this->coverageGapsAccepted, $this->combinedAttempts, $this->failure, $this->exposed);
    }

    /** @return list<FindingPlan> findings that count towards the exit code */
    public function gated(): array
    {
        return array_values(array_filter($this->findings, fn (FindingPlan $p): bool => $this->countsForExit($p)));
    }

    /** Number of advisories across all packages. */
    public function advisoryCount(): int
    {
        return array_sum(array_map(static fn (FindingPlan $p): int => count($p->allFindings()), $this->findings));
    }

    /** @return list<FindingPlan> */
    public function unsolved(): array
    {
        return array_values(array_filter($this->findings, static fn (FindingPlan $p): bool => !$p->hasRemediation()));
    }

    /** @param array<string, string> $overrides */
    public function withMetadata(array $overrides): self
    {
        return new self($this->findings, array_replace($this->metadata, $overrides), $this->warnings, $this->combined, $this->failOn, $this->inventory, $this->baseline, $this->coverageGaps, $this->coverageGapsAccepted, $this->combinedAttempts, $this->failure, $this->exposed);
    }

    public function exitCode(): int
    {
        if ($this->failure !== null) {
            return $this->failure;
        }
        $gated = $this->gated();
        if ($gated === []) {
            // Nothing found, but records about locked packages could not be read: the source cannot vouch
            // for this lock, and a gate must not read that as clean unless the operator accepted the gaps.
            return $this->coverageGaps !== [] && !$this->coverageGapsAccepted ? self::EXIT_ADVISORIES_UNAVAILABLE : self::EXIT_CLEAN;
        }
        // A finding without a fix of its own is still remediated when the verified combined command
        // fixes every advisory on it (a parent's update removing the vulnerable child): the gate asks
        // whether a verified fix exists for each gated finding, whatever --fail-on or the baseline left out.
        $fixedByCombined = $this->combined === null ? [] : array_flip($this->combined->fixedKeys);
        $unsolved = array_values(array_filter($gated, static function (FindingPlan $p) use ($fixedByCombined): bool {
            if ($p->hasRemediation()) {
                return false;
            }
            if ($fixedByCombined === []) {
                return true;
            }
            foreach ($p->allFindings() as $finding) {
                if (!isset($fixedByCombined[$finding->key()])) {
                    return true;
                }
            }

            return false;
        }));
        if ($unsolved !== []) {
            // A finding without a fix because the tool or the network failed is not "no fix exists":
            // report the infrastructure problem so a gate cannot mistake a broken planner for a clean state.
            foreach ($unsolved as $plan) {
                if ($plan->infrastructureFailure === SolveStatus::Error) {
                    return self::EXIT_ERROR;
                }
            }
            foreach ($unsolved as $plan) {
                if ($plan->infrastructureFailure === SolveStatus::Transport) {
                    return self::EXIT_SOLVER_FAILURE;
                }
            }

            return self::EXIT_NO_REMEDIATION;
        }

        return self::EXIT_REMEDIATION_AVAILABLE;
    }
}
