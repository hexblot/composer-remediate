<?php

declare(strict_types=1);

namespace Remediate\Engine\Advisory\Db;

/** The database file a run reads, with how it was established as the one to read. */
final class LocatedDatabase
{
    public function __construct(
        public readonly string $path,
        public readonly Freshness $freshness,
        /** One sentence for the report header, e.g. "confirmed current against …, built 3 hours ago". */
        public readonly string $provenance,
    ) {
    }
}
