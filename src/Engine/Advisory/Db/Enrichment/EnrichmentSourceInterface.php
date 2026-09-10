<?php

declare(strict_types=1);

namespace Remediate\Engine\Advisory\Db\Enrichment;

/**
 * A feed that says something about CVEs rather than about packages (exploit probability, known
 * exploitation). Enrichment is optional data: a source that cannot be fetched is reported in the
 * build's metadata and the database is built without it.
 */
interface EnrichmentSourceInterface
{
    /** Short name used in metadata, e.g. "EPSS", "KEV". */
    public function name(): string;

    /**
     * @param callable(string): void $log
     *
     * @return array{records: array<string, ExploitRecord>, meta: array<string, string>} records keyed by upper-case CVE id
     *
     * @throws \RuntimeException when the feed cannot be fetched or parsed
     */
    public function fetch(callable $log): array;
}
