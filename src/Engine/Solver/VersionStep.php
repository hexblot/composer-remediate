<?php

declare(strict_types=1);

namespace Remediate\Engine\Solver;

enum VersionStep: string
{
    case Major = 'major';
    case Minor = 'minor';
    case Patch = 'patch';
    case Other = 'other';

    /** Rough magnitude used for the "smallest version movement" tie-breaker. */
    public function weight(): int
    {
        return match ($this) {
            self::Major => 10000,
            self::Minor => 100,
            self::Patch => 1,
            self::Other => 500,
        };
    }
}
