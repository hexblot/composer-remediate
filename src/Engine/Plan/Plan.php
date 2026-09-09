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
    public function __construct(
        public readonly array $findings,
        public readonly array $metadata,
        public readonly array $warnings = [],
        public readonly ?CombinedRemediation $combined = null,
    ) {
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
        return new self($this->findings, array_replace($this->metadata, $overrides), $this->warnings, $this->combined);
    }

    public function exitCode(): int
    {
        if ($this->findings === []) {
            return self::EXIT_CLEAN;
        }
        $unsolved = $this->unsolved();
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
