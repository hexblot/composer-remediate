<?php

declare(strict_types=1);

namespace Remediate\Engine\Plan;

use Remediate\Engine\Candidate\Candidate;

/**
 * One step of the global search for a command that fixes every finding: which combination was
 * tried, why, and what came of it. The report lists these so a reader can see why the combined
 * command is what it is and why smaller or different ones were not chosen.
 */
final class CombinedAttempt
{
    /**
     * @param string      $note    what this attempt changed compared with the previous one, in words
     * @param string|null $reason  the solver's explanation or the acceptance rule that failed
     * @param bool        $chosen  whether this is the combination the report recommends
     */
    public function __construct(
        public readonly Candidate $candidate,
        public readonly CombinedOutcome $outcome,
        public readonly string $note,
        public readonly int $fixed,
        public readonly int $total,
        public readonly ?string $reason = null,
        public readonly bool $chosen = false,
    ) {
    }

    public function withChosen(bool $chosen): self
    {
        return new self($this->candidate, $this->outcome, $this->note, $this->fixed, $this->total, $this->reason, $chosen);
    }
}
