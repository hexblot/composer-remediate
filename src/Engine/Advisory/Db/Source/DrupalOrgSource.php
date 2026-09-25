<?php

declare(strict_types=1);

namespace Remediate\Engine\Advisory\Db\Source;

use Composer\Util\HttpDownloader;
use Remediate\Engine\Advisory\Db\CoverageGap;
use Remediate\Engine\Advisory\Db\NormalizedAdvisory;

/**
 * Drupal.org's security advisories, from the Composer repository every Drupal project configures
 * (packages.drupal.org/8). Drupal contrib advisories (SA-CONTRIB-…) are published only there: Packagist,
 * OSV and FriendsOfPHP do not carry them, so a database without this feed reports drupal/webform clean
 * while `composer audit` does not. The dump is in the Packagist API shape.
 *
 * OSV republishes Drupal core advisories under its own identifiers: SA-CORE-2026-013 is
 * DRUPAL-CORE-2026-013 there, with the same ranges and usually no CVE to join them on. The OSV form is
 * added as an alias, so the two merge into one advisory instead of reporting every core advisory twice.
 * It is a fixed renaming of one identifier scheme into another, not a guess from similar content.
 *
 * The repository declares that it serves drupal/* and nothing else, so that is all it may speak for: a
 * record about any other package is not taken as an advisory, and is recorded as a coverage gap on
 * that package rather than dropped.
 */
final class DrupalOrgSource implements AdvisorySourceInterface
{
    public const URL = 'https://packages.drupal.org/8/security-advisories?updatedSince=1';

    /** @var list<CoverageGap> */
    private array $gaps = [];

    public function __construct(
        private readonly HttpDownloader $downloader,
        private readonly PackagistShapeMapper $mapper = new PackagistShapeMapper(),
        private readonly string $url = self::URL,
    ) {
    }

    public function name(): string
    {
        return 'Drupal.org';
    }

    public function fetch(callable $log): array
    {
        $log('Drupal.org: downloading the advisory dump…');
        $data = $this->downloader->get($this->url)->decodeJson();
        if (!is_array($data)) {
            throw new \RuntimeException('Drupal.org advisory dump is not a JSON object');
        }
        $result = $this->mapper->mapDocument($data, $this->name());
        $this->gaps = $result['gaps'];
        $records = [];
        foreach ($result['records'] as $record) {
            $outside = self::outsideDrupal($record);
            if ($outside === []) {
                $records[] = self::withOsvAlias($record);
                continue;
            }
            foreach ($outside as $package) {
                $this->gaps[] = new CoverageGap($this->name(), $record->canonicalId, $package, 'packages.drupal.org serves drupal/* only and does not speak for this package');
            }
        }
        $log(sprintf('Drupal.org: %d records%s', count($records), count($this->gaps) > 0 ? sprintf(', %d recorded as coverage gaps', count($this->gaps)) : ''));
        if ($records === [] && $this->gaps === []) {
            throw new \RuntimeException('Drupal.org returned no advisories at all, and nothing it could not read either. A feed that answers successfully with no data is an outage, not an empty world; the build stops rather than publish a database missing this source.');
        }

        return $records;
    }

    public function gaps(): array
    {
        return $this->gaps;
    }

    /** The record with the identifier OSV gives the same advisory (SA-CORE-… as DRUPAL-CORE-…) among its aliases. */
    private static function withOsvAlias(NormalizedAdvisory $record): NormalizedAdvisory
    {
        $extra = [];
        foreach ($record->aliases as $alias) {
            if (preg_match('{^SA-(CORE|CONTRIB)-(\d{4}-\d+)$}i', $alias, $m) === 1) {
                $extra[] = 'DRUPAL-' . strtoupper($m[1]) . '-' . $m[2];
            }
        }
        $aliases = array_values(array_unique([...$record->aliases, ...$extra]));
        if ($aliases === $record->aliases) {
            return $record;
        }

        return new NormalizedAdvisory($record->canonicalId, $aliases, $record->title, $record->link, $record->severity, $record->reportedAt, $record->withdrawnAt, $record->affected, $record->sources, $record->conflicts);
    }

    /** @return list<string> the packages a record names outside drupal/* */
    private static function outsideDrupal(NormalizedAdvisory $record): array
    {
        $outside = [];
        foreach ($record->affected as $range) {
            if (!str_starts_with($range->package, 'drupal/')) {
                $outside[] = $range->package;
            }
        }

        return array_values(array_unique($outside));
    }
}
