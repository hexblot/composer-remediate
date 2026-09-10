<?php

declare(strict_types=1);

namespace Remediate\Engine\Advisory\Db;

/** How the advisory database in use came to be trusted as current, or why it is not. */
enum Freshness: string
{
    /** The local copy matches the published database (same sha256 or dataset hash) or is a newer local build. */
    case Confirmed = 'confirmed';
    /** The local copy was missing or stale and was replaced by a download. */
    case Downloaded = 'downloaded';
    /** The local copy was missing or stale and was rebuilt from the sources. */
    case Rebuilt = 'rebuilt';
    /** No source could be reached; the local copy is used and its age is reported. */
    case Unconfirmed = 'unconfirmed';
    /** Offline mode: the local copy is used without any check. */
    case Offline = 'offline';
    /** A local file named by --database-location, read as it is. */
    case Explicit = 'explicit';
}
