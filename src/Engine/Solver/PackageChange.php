<?php

declare(strict_types=1);

namespace Remediate\Engine\Solver;

use Composer\Semver\Comparator;

final class PackageChange
{
    public const ADDED = 'added';
    public const REMOVED = 'removed';
    public const UPGRADED = 'upgraded';
    public const DOWNGRADED = 'downgraded';
    public const CHANGED = 'changed';

    /**
     * @param self::* $kind
     */
    public function __construct(
        public readonly string $packageName,
        public readonly string $kind,
        public readonly ?string $fromPretty,
        public readonly ?string $toPretty,
        public readonly ?string $fromNormalized,
        public readonly ?string $toNormalized,
        public readonly ?VersionStep $step,
    ) {
    }

    public static function added(string $name, string $pretty, string $normalized): self
    {
        return new self($name, self::ADDED, null, $pretty, null, $normalized, null);
    }

    public static function removed(string $name, string $pretty, string $normalized): self
    {
        return new self($name, self::REMOVED, $pretty, null, $normalized, null, null);
    }

    public static function between(string $name, string $fromPretty, string $fromNormalized, string $toPretty, string $toNormalized): self
    {
        $step = self::classify($fromNormalized, $toNormalized);
        if ($step === VersionStep::Other) {
            $kind = self::CHANGED;
        } else {
            $kind = Comparator::lessThan($toNormalized, $fromNormalized) ? self::DOWNGRADED : self::UPGRADED;
        }

        return new self($name, $kind, $fromPretty, $toPretty, $fromNormalized, $toNormalized, $step);
    }

    public function isVersionChange(): bool
    {
        return $this->kind === self::UPGRADED || $this->kind === self::DOWNGRADED || $this->kind === self::CHANGED;
    }

    public function describe(): string
    {
        return match ($this->kind) {
            self::ADDED => sprintf('%s added (%s)', $this->packageName, $this->toPretty),
            self::REMOVED => sprintf('%s removed (was %s)', $this->packageName, $this->fromPretty),
            default => sprintf('%s %s -> %s', $this->packageName, $this->fromPretty, $this->toPretty),
        };
    }

    private static function classify(string $from, string $to): VersionStep
    {
        $a = self::numericParts($from);
        $b = self::numericParts($to);
        if ($a === null || $b === null) {
            return VersionStep::Other;
        }
        if ($a[0] !== $b[0]) {
            return VersionStep::Major;
        }
        if ($a[1] !== $b[1]) {
            return VersionStep::Minor;
        }

        return VersionStep::Patch;
    }

    /** @return array{int, int, int, int}|null */
    private static function numericParts(string $normalized): ?array
    {
        if (str_starts_with($normalized, 'dev-') || str_ends_with($normalized, '-dev') && str_starts_with($normalized, '9999999')) {
            return null;
        }
        $numeric = explode('-', $normalized)[0];
        if (preg_match('{^\d+(\.\d+){0,3}$}', $numeric) !== 1) {
            return null;
        }
        $parts = array_map('intval', explode('.', $numeric));

        return [$parts[0], $parts[1] ?? 0, $parts[2] ?? 0, $parts[3] ?? 0];
    }
}
