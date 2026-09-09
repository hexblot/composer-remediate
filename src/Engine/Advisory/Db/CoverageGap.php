<?php

declare(strict_types=1);

namespace Remediate\Engine\Advisory\Db;

/**
 * An upstream advisory record that a database build could not interpret (unparsable range, no
 * version data). The record is not in the database, so the package it names is treated as
 * unaffected by it; the gap is stored so a consumer can see that this was a failure to read the
 * record, not a statement that the package is safe.
 */
final class CoverageGap
{
    public function __construct(
        public readonly string $source,
        public readonly string $remoteId,
        public readonly ?string $package,
        public readonly string $reason,
        public readonly ?string $raw = null,
    ) {
    }

    public function describe(): string
    {
        return sprintf('%s record %s%s could not be interpreted at database build (%s%s)', $this->source, $this->remoteId, $this->package !== null ? ' for ' . $this->package : '', $this->reason, $this->raw !== null ? ': ' . $this->raw : '');
    }
}
