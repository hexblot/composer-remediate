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
    ) {
    }

    /** The caller has read the coverage gaps and accepts the lock as clean despite them (--accept-coverage-gaps). */
    public function withAcceptedCoverageGaps(): self
    {
        return new self($this->findings, $this->metadata, $this->warnings, $this->combined, $this->failOn, $this->inventory, $this->baseline, $this->coverageGaps, true, $this->combinedAttempts);
    }

    public function withFailOn(?string $severity): self
    {
        if ($severity !== null && Severity::fromLabel($severity) === null) {
            throw new \InvalidArgumentException(sprintf('Unknown severity "%s"; use one of %s.', $severity, Severity::labels()));
        }

        return new self($this->findings, $this->metadata, $this->warnings, $this->combined, $severity !== null ? strtolower($severity) : null, $this->inventory, $this->baseline, $this->coverageGaps, $this->coverageGapsAccepted, $this->combinedAttempts);
    }

    /** @param list<string> $keys finding keys (advisory@package) */
    public function withBaseline(array $keys): self
    {
        $baseline = [];
        foreach ($keys as $key) {
            $baseline[strtolower($key)] = true;
        }

        return new self($this->findings, $this->metadata, $this->warnings, $this->combined, $this->failOn, $this->inventory, $baseline, $this->coverageGaps, $this->coverageGapsAccepted, $this->combinedAttempts);
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

    /** Whether a finding counts towards the exit code under the severity threshold and the baseline. */
    public function countsForExit(FindingPlan $plan): bool
    {
        if ($this->isBaselined($plan)) {
            return false;
        }
        if ($this->failOn === null) {
            return true;
        }
        $threshold = Severity::fromLabel($this->failOn)?->rank() ?? 0;
        foreach ($plan->allFindings() as $finding) {
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
        return new self($this->findings, $this->metadata, [...$this->warnings, ...$warnings], $this->combined, $this->failOn, $this->inventory, $this->baseline, $this->coverageGaps, $this->coverageGapsAccepted, $this->combinedAttempts);
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
        return new self($this->findings, array_replace($this->metadata, $overrides), $this->warnings, $this->combined, $this->failOn, $this->inventory, $this->baseline, $this->coverageGaps, $this->coverageGapsAccepted, $this->combinedAttempts);
    }

    public function exitCode(): int
    {
        $gated = $this->gated();
        if ($gated === []) {
            // Nothing found, but records about locked packages could not be read: the source cannot vouch
            // for this lock, and a gate must not read that as clean unless the operator accepted the gaps.
            return $this->coverageGaps !== [] && !$this->coverageGapsAccepted ? self::EXIT_ADVISORIES_UNAVAILABLE : self::EXIT_CLEAN;
        }
        // A finding without a fix of its own is still remediated when the combined command fixes it
        // (a parent's update removing the vulnerable child): the gate asks whether a verified fix exists.
        $fixedByCombined = $this->combined !== null && $this->combined->fixesAll() ? array_flip($this->combined->fixedKeys) : [];
        $unsolved = array_values(array_filter($gated, static function (FindingPlan $p) use ($fixedByCombined): bool {
            if ($p->hasRemediation()) {
                return false;
            }
            foreach ($p->allFindings() as $finding) {
                if (!isset($fixedByCombined[$finding->key()])) {
                    return true;
                }
            }

            return $fixedByCombined === [];
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
