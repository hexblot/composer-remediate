<?php

declare(strict_types=1);

namespace Remediate\Engine\Candidate;

enum Strategy: string
{
    case LockRefresh = 'lock-refresh';
    case WithDependencies = 'with-dependencies';
    case ParentUpdate = 'parent-update';
    case RootConstraintWiden = 'root-constraint-widen';
    case DirectRequire = 'direct-require';

    /** Lower is preferred when everything else is equal. */
    public function rank(): int
    {
        return match ($this) {
            self::LockRefresh => 0,
            self::WithDependencies => 1,
            self::ParentUpdate => 2,
            self::RootConstraintWiden => 3,
            self::DirectRequire => 4,
        };
    }

    public function label(): string
    {
        return match ($this) {
            self::LockRefresh => 'update the vulnerable package only',
            self::WithDependencies => 'update the vulnerable package with its dependencies',
            self::ParentUpdate => 'update the controlling parent with all dependencies',
            self::RootConstraintWiden => 'widen a root constraint to the next major, then update',
            self::DirectRequire => 'take direct ownership of the vulnerable package',
        };
    }
}
