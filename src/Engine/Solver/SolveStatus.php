<?php

declare(strict_types=1);

namespace Remediate\Engine\Solver;

enum SolveStatus: string
{
    case Resolved = 'resolved';
    case Conflict = 'conflict';
    case Transport = 'transport-error';
    case Error = 'error';
}
