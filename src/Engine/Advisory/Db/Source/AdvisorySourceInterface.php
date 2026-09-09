<?php

declare(strict_types=1);

namespace Remediate\Engine\Advisory\Db\Source;

use Remediate\Engine\Advisory\Db\CoverageGap;
use Remediate\Engine\Advisory\Db\NormalizedAdvisory;

interface AdvisorySourceInterface
{
    /** Short name used in provenance records, e.g. "Packagist", "OSV", "FriendsOfPHP". */
    public function name(): string;

    /**
     * Fetches every advisory this source knows for the Packagist ecosystem, one record per upstream entry.
     *
     * @param callable(string): void $log
     *
     * @return list<NormalizedAdvisory>
     *
     * @throws \RuntimeException when the source cannot be fetched or parsed
     */
    public function fetch(callable $log): array;

    /**
     * Records the last fetch() could not interpret and therefore left out. Each names the package
     * whose coverage is incomplete when the record said which package it was about.
     *
     * @return list<CoverageGap>
     */
    public function gaps(): array;
}
