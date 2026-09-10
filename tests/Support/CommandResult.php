<?php

declare(strict_types=1);

namespace Remediate\Tests\Support;

/**
 * What one command run produced: exit code, standard output (the report) and standard error
 * (Composer's IO: diagnostics, warnings, "report written to" notices).
 */
final class CommandResult
{
    public function __construct(
        public readonly int $exitCode,
        public readonly string $stdout,
        public readonly string $stderr,
    ) {
    }

    /** @return array<string, mixed> the standard output decoded as a JSON object */
    public function json(): array
    {
        $decoded = json_decode($this->stdout, true, 512, JSON_THROW_ON_ERROR);
        if (!is_array($decoded)) {
            throw new \RuntimeException('standard output is not a JSON object: ' . $this->stdout);
        }
        /** @var array<string, mixed> $decoded */
        return $decoded;
    }

    /** Everything a failing assertion needs to explain itself. */
    public function describe(): string
    {
        return sprintf("exit %d\n--- stdout ---\n%s\n--- stderr ---\n%s", $this->exitCode, $this->stdout, $this->stderr);
    }
}
