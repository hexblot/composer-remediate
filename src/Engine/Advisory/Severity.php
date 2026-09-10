<?php

declare(strict_types=1);

namespace Remediate\Engine\Advisory;

/**
 * The severity labels advisories carry, ranked. Packagist and GitHub use "moderate" where others use
 * "medium"; the two are the same rank. An advisory without a label, or with one not listed here, has
 * no Severity and is treated as the most severe for gating and the least urgent for ordering.
 */
enum Severity: string
{
    case Low = 'low';
    case Medium = 'medium';
    case High = 'high';
    case Critical = 'critical';

    /** Case-insensitive; "moderate" maps to Medium. Null for unknown or missing labels. */
    public static function fromLabel(?string $label): ?self
    {
        if ($label === null) {
            return null;
        }
        $label = strtolower($label);

        return $label === 'moderate' ? self::Medium : self::tryFrom($label);
    }

    /** 1 for low up to 4 for critical. */
    public function rank(): int
    {
        return match ($this) {
            self::Low => 1,
            self::Medium => 2,
            self::High => 3,
            self::Critical => 4,
        };
    }

    /** The labels accepted by --fail-on, for messages. */
    public static function labels(): string
    {
        return implode(', ', [...array_map(static fn (self $s): string => $s->value, self::cases()), 'moderate']);
    }
}
