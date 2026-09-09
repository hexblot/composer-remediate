<?php

declare(strict_types=1);

namespace Remediate\Engine\Plan;

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
    public const SEVERITIES = ['low' => 1, 'medium' => 2, 'moderate' => 2, 'high' => 3, 'critical' => 4];

    /**
     * @param list<FindingPlan>     $findings
     * @param array<string, string> $metadata
     * @param list<string>          $warnings
     * @param string|null           $failOn    severity threshold for the exit code: findings whose advisories are all
     *                                         below it do not affect the exit code (unknown severity always counts)
     * @param list<array{name: string, version: string, dev: bool}> $inventory every locked package, for SBOM output
     * @param array<string, true> $baseline finding keys (advisory@package) accepted earlier; they are reported but do not affect the exit code
     */
    public function __construct(
        public readonly array $findings,
        public readonly array $metadata,
        public readonly array $warnings = [],
        public readonly ?CombinedRemediation $combined = null,
        public readonly ?string $failOn = null,
        public readonly array $inventory = [],
        public readonly array $baseline = [],
    ) {
    }

    public function withFailOn(?string $severity): self
    {
        if ($severity !== null && !isset(self::SEVERITIES[strtolower($severity)])) {
            throw new \InvalidArgumentException(sprintf('Unknown severity "%s"; use one of %s.', $severity, implode(', ', array_keys(self::SEVERITIES))));
        }

        return new self($this->findings, $this->metadata, $this->warnings, $this->combined, $severity !== null ? strtolower($severity) : null, $this->inventory, $this->baseline);
    }

    /** @param list<string> $keys finding keys (advisory@package) */
    public function withBaseline(array $keys): self
    {
        $baseline = [];
        foreach ($keys as $key) {
            $baseline[strtolower($key)] = true;
        }

        return new self($this->findings, $this->metadata, $this->warnings, $this->combined, $this->failOn, $this->inventory, $baseline);
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
        $threshold = self::SEVERITIES[$this->failOn];
        foreach ($plan->allFindings() as $finding) {
            $severity = $finding->advisory->severity;
            if ($severity === null || (self::SEVERITIES[strtolower($severity)] ?? 0) >= $threshold) {
                return true;
            }
        }

        return false;
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
        return new self($this->findings, array_replace($this->metadata, $overrides), $this->warnings, $this->combined, $this->failOn, $this->inventory, $this->baseline);
    }

    public function exitCode(): int
    {
        $gated = $this->gated();
        if ($gated === []) {
            return self::EXIT_CLEAN;
        }
        $unsolved = array_values(array_filter($gated, static fn (FindingPlan $p): bool => !$p->hasRemediation()));
        if ($unsolved !== []) {
            foreach ($unsolved as $plan) {
                if ($plan->blocker === null || !str_contains($plan->blocker, 'network')) {
                    return self::EXIT_NO_REMEDIATION;
                }
            }

            return self::EXIT_SOLVER_FAILURE;
        }

        return self::EXIT_REMEDIATION_AVAILABLE;
    }
}
