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
        /**
         * The sha256 of the bytes this decision was made about — the ones that were inspected or
         * verified, never a fresh hash of the path afterwards. Rehashing the path asks the file who it
         * is a second time, and a file replaced between the two answers is believed on the second: the
         * check runs against the old bytes and the pin is then stamped with the new ones.
         *
         * Required, so that a decision cannot be made without saying which bytes it is about.
         */
        public readonly string $digest,
    ) {
    }
}
