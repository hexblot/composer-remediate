<?php

declare(strict_types=1);

namespace Remediate\Engine\Apply;

/** What `--apply` did. */
enum ApplyOutcome: string
{
    /** The recommended command ran and Composer reported success. */
    case Applied = 'applied';
    /** Nothing ran: a precondition was not met, and the reason says which. */
    case Refused = 'refused';
    /** The command ran and Composer failed; the project is as Composer left it, and a backup exists. */
    case Failed = 'failed';
}
