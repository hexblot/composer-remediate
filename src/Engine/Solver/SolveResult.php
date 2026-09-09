<?php

declare(strict_types=1);

namespace Remediate\Engine\Solver;

use Remediate\Engine\Lock\LockSnapshot;

final class SolveResult
{
    public function __construct(
        public readonly SolveStatus $status,
        public readonly ?LockSnapshot $after,
        public readonly string $output,
        public readonly ?string $message = null,
        public readonly int $exitCode = 0,
    ) {
    }

    public function resolved(): bool
    {
        return $this->status === SolveStatus::Resolved && $this->after !== null;
    }

    /** The solver's own explanation, trimmed to the interesting part. */
    public function explanation(): string
    {
        if ($this->message !== null && $this->message !== '') {
            return $this->message;
        }
        $output = $this->output;
        $pos = strpos($output, 'Your requirements could not be resolved');
        if ($pos !== false) {
            $output = substr($output, $pos);
        }
        $lines = array_values(array_filter(array_map('rtrim', explode("\n", $output)), static fn (string $l): bool => $l !== ''));

        return implode("\n", array_slice($lines, 0, 25));
    }
}
