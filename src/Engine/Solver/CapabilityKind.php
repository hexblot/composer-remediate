<?php

declare(strict_types=1);

namespace Remediate\Engine\Solver;

/**
 * A way an update changes what a package is allowed to do, as opposed to how much it changes. The
 * count of changed packages measures review burden; these measure reach.
 */
enum CapabilityKind: string
{
    /** The package type changed. `composer-plugin` is the one that runs code during Composer itself. */
    case Type = 'type';
    /** `autoload.files` entries appeared or grew: code that runs on every request, unasked. */
    case AutoloadFiles = 'autoload_files';
    /** Binaries appeared or grew: executables linked into the project's bin directory. */
    case Binaries = 'binaries';
    /** The host serving the source repository changed. */
    case SourceHost = 'source_host';
    /** The host serving the dist archive changed. */
    case DistHost = 'dist_host';
}
