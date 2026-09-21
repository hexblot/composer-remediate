<?php

declare(strict_types=1);

namespace Remediate\Engine\Solver;

/**
 * One capability a package gains, loses or moves as a result of an update: a change in what the
 * installed code can do, rather than in how much of it changes.
 *
 * Everything here is read from metadata the lock file and the solve already carry, so nothing is
 * downloaded or unpacked to produce it. It is shown next to a recommendation rather than folded
 * into the ranking, because it answers a different question from the size of the change.
 */
final class CapabilityChange
{
    public function __construct(
        public readonly string $packageName,
        public readonly CapabilityKind $kind,
        public readonly ?string $from,
        public readonly string $to,
    ) {
    }

    /** True for the changes that let code run which could not run before. */
    public function runsNewCode(): bool
    {
        return match ($this->kind) {
            CapabilityKind::Type => $this->to === 'composer-plugin',
            CapabilityKind::AutoloadFiles, CapabilityKind::Binaries => true,
            default => false,
        };
    }

    public function describe(): string
    {
        return match ($this->kind) {
            CapabilityKind::Type => $this->from === null
                ? sprintf('%s is a %s', $this->packageName, $this->to)
                : sprintf('%s changes type: %s -> %s', $this->packageName, $this->from, $this->to),
            CapabilityKind::AutoloadFiles => $this->from === null
                ? sprintf('%s autoloads files on every request: %s', $this->packageName, $this->to)
                : sprintf('%s changes the files it autoloads on every request: %s -> %s', $this->packageName, $this->from, $this->to),
            CapabilityKind::Binaries => $this->from === null
                ? sprintf('%s installs binaries: %s', $this->packageName, $this->to)
                : sprintf('%s changes the binaries it installs: %s -> %s', $this->packageName, $this->from, $this->to),
            CapabilityKind::SourceHost => sprintf('%s is fetched from a different source host: %s -> %s', $this->packageName, $this->from ?? '(none)', $this->to),
            CapabilityKind::DistHost => sprintf('%s is fetched from a different dist host: %s -> %s', $this->packageName, $this->from ?? '(none)', $this->to),
        };
    }
}
