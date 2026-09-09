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
     * @param string|null           $failOn   severity threshold for the exit code: findings whose advisories are all
     *                                        below it do not affect the exit code (unknown severity always counts)
     */
    public function __construct(
        public readonly array $findings,
        public readonly array $metadata,
        public readonly array $warnings = [],
        public readonly ?CombinedRemediation $combined = null,
        public readonly ?string $failOn = null,
    ) {
    }

    public function withFailOn(?string $severity): self
    {
        if ($severity !== null && !isset(self::SEVERITIES[strtolower($severity)])) {
            throw new \InvalidArgumentException(sprintf('Unknown severity "%s"; use one of %s.', $severity, implode(', ', array_keys(self::SEVERITIES))));
        }

        return new self($this->findings, $this->metadata, $this->warnings, $this->combined, $severity !== null ? strtolower($severity) : null);
    }

    /** Whether a finding counts towards the exit code under the configured threshold. */
    public function countsForExit(FindingPlan $plan): bool
    {
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
        return new self($this->findings, array_replace($this->metadata, $overrides), $this->warnings, $this->combined, $this->failOn);
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
