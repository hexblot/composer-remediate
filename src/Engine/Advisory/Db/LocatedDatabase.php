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
         * The sha256 of the bytes this decision was made about. Whatever reads the file afterwards has
         * to arrive at these, or it is reading something nobody decided anything about: verifying a
         * download and then opening a path are two statements, and only this ties them together.
         */
        public readonly ?string $digest = null,
    ) {
    }

    public function withDigest(?string $digest): self
    {
        return new self($this->path, $this->freshness, $this->provenance, $digest);
    }
}
