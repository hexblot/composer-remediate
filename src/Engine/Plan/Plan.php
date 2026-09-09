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
    ) {
    }

    public function exitCode(): int
    {
        if ($this->findings === []) {
            return self::EXIT_CLEAN;
        }
        foreach ($this->findings as $plan) {
            if (!$plan->hasRemediation()) {
                return self::EXIT_NO_REMEDIATION;
            }
        }

        return self::EXIT_REMEDIATION_AVAILABLE;
    }
}
