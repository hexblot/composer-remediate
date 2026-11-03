<?php

declare(strict_types=1);

namespace Remediate\Tests\Support;

use Remediate\Engine\Advisory\Db\AffectedRange;
use Remediate\Engine\Advisory\Db\CoverageGap;
use Remediate\Engine\Advisory\Db\NormalizedAdvisory;
use Remediate\Engine\Advisory\Db\Source\AdvisorySourceInterface;
use Remediate\Engine\Advisory\Db\SourceRecord;

/**
 * An advisory feed with the records a test hands it, under the name a test gives it. The feeds
 * themselves live in the release channel; what the plugin's tests need is a database built from a
 * feed of a given name, which is what the locator reads back when it decides whether a local build
 * can stand in for the published database.
 */
final class ScriptedSource implements AdvisorySourceInterface
{
    /**
     * @param list<NormalizedAdvisory> $records
     * @param list<CoverageGap>        $gaps
     */
    public function __construct(
        private readonly string $name,
        private readonly array $records,
        private readonly array $gaps = [],
    ) {
    }

    /** One advisory on one package: the record a feed would produce for it. */
    public static function advisory(string $feed, string $id, string $package, string $affectedVersions, ?string $cve = null, ?string $title = null, ?string $reportedAt = null): NormalizedAdvisory
    {
        $range = new AffectedRange($package, $affectedVersions, $feed);

        return new NormalizedAdvisory(
            $id,
            array_values(array_unique(array_filter([$id, $cve]))),
            $title ?? sprintf('Synthetic %s advisory for %s', $feed, $package),
            'https://example.invalid/advisories/' . $id,
            'high',
            $reportedAt !== null ? new \DateTimeImmutable($reportedAt) : null,
            null,
            [$range],
            [new SourceRecord($feed, $id)],
        );
    }

    public function name(): string
    {
        return $this->name;
    }

    public function fetch(callable $log): array
    {
        $log(sprintf('%s: %d records', $this->name, count($this->records)));

        return $this->records;
    }

    public function gaps(): array
    {
        return $this->gaps;
    }
}
