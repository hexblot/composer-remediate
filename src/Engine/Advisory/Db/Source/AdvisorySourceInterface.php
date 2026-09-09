<?php

declare(strict_types=1);

namespace Remediate\Engine\Advisory\Db\Source;

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
}
